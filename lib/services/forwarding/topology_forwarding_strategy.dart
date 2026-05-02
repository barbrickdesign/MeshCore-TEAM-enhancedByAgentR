// Copyright (c) 2026 tmacinc
// Licensed under CC BY-NC-SA 4.0

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:meshcore_team/models/network_topology.dart';
import 'package:meshcore_team/models/telemetry_event.dart';
import 'package:meshcore_team/models/topology_event.dart';
import 'package:meshcore_team/services/forwarding/forwarding_strategy.dart';
import 'package:meshcore_team/services/forwarding/forwarding_v1_strategy.dart';

/// Forwarding V2 strategy: topology-aware routing using the live #T: mesh graph.
///
/// Algorithm:
///   • Uses [NetworkTopology] to determine the actual hop distance from the
///     local companion device to each tracked contact.
///   • For each tracked contact in the map-visible window:
///       - hopDist = 0  → direct neighbour (no forwarding needed)
///       - hopDist > 0  → multi-hop; include in forward list and maxHops calc
///       - hopDist null → unknown reachability (topology not yet converged or
///                        the contact has never broadcast a #T: message);
///                        conservatively treated as multi-hop
///   • maxHops = max(hop distances across contacts needing forwarding),
///     clamped to [1.._maxHopsCeiling].
///   • SET_FORWARD_LIST is populated with the 6-byte public-key prefixes of
///     all multi-hop / unknown contacts so the firmware routes packets to them.
///   • Hold-down: when ALL tracked contacts become direct (hopDist = 0),
///     a [_holdDuration] countdown starts.  If no contact re-triggers during
///     the hold, maxHops drops to 0 and the forward list is cleared.
///     If re-triggered, the hold is cancelled and forwarding resumes immediately.
///   • Falls back to [ForwardingV1Strategy] output (with the 'topology' mode
///     key label) when [_localPrefix] is not yet set — i.e. immediately after
///     a fresh connect before the companion key has been registered.
class TopologyForwardingStrategy implements ForwardingStrategy {
  static const int _maxHopsCeiling = 4;
  static const Duration _holdDuration = Duration(minutes: 5);

  /// Conservative hop-count assumed for contacts whose topology is unknown.
  ///
  /// A value of 2 means we treat an unknown-reachability contact as if it
  /// were two hops away: enough to activate forwarding without over-estimating
  /// the network radius.  The firmware's actual hop count is bounded by
  /// [_maxHopsCeiling] regardless.
  static const int _unknownHopDefault = 2;

  final ForwardingV1Strategy _fallback;
  final NetworkTopology _topology;

  /// Called when internal state changes and a fresh [compute] push is needed
  /// (e.g. hold-down timer expired).  Wired by [ForwardingPolicyService].
  final VoidCallback? onStateChanged;

  /// 12-char lowercase hex prefix of the local companion device.
  /// Set by [ForwardingPolicyService.updateCompanionPrefix] whenever the
  /// active companion changes.
  String? _localPrefix;

  int _currentMaxHops = 0;
  bool _holdActive = false;
  Timer? _holdTimer;

  TopologyForwardingStrategy({
    required ForwardingV1Strategy fallback,
    required NetworkTopology topology,
    this.onStateChanged,
  })  : _fallback = fallback,
        _topology = topology;

  // ---------------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------------

  /// Update the local companion prefix from the full companion public-key hex
  /// string.  Only the first 12 characters (6 bytes) are used.
  void updateLocalPrefix(String? companionKeyHex) {
    if (companionKeyHex == null || companionKeyHex.length < 12) {
      _localPrefix = null;
      return;
    }
    _localPrefix = companionKeyHex.substring(0, 12).toLowerCase();
    debugPrint('[TopologyV2] Local prefix set to $_localPrefix');
  }

  // ---------------------------------------------------------------------------
  // ForwardingStrategy interface
  // ---------------------------------------------------------------------------

  @override
  String get modeKey => 'topology';

  /// Forward TEL events to the V1 fallback so its state stays current
  /// while topology strategy is active.
  @override
  void onTelemetry(TelemetryEvent event) => _fallback.onTelemetry(event);

  /// Forward topology events to V1 fallback so its state stays current.
  @override
  void onTopology(TopologyEvent event) => _fallback.onTopology(event);

  @override
  void reset() {
    _cancelHold();
    _currentMaxHops = 0;
    _fallback.reset();
    debugPrint('[TopologyV2] State reset');
  }

  @override
  ForwardingDecision compute(ForwardingStrategyInput input) {
    final localPrefix = _localPrefix;

    // No local prefix yet — fall back to V1 with the topology mode label so
    // the debug screen shows the correct strategy name.
    if (localPrefix == null || localPrefix.isEmpty) {
      final fb = _fallback.compute(input);
      return ForwardingDecision(
        maxHops: fb.maxHops,
        prefixes: fb.prefixes,
        strategyMode: modeKey,
        reason: 'No local prefix yet; V1 fallback: ${fb.reason}',
        needsForwarding: fb.needsForwarding,
        maxPathObserved: fb.maxPathObserved,
      );
    }

    if (input.contacts.isEmpty) {
      _cancelHold();
      _currentMaxHops = 0;
      return const ForwardingDecision(
        maxHops: 0,
        prefixes: [],
        strategyMode: 'topology',
        reason: 'No tracked contacts',
        needsForwarding: false,
        maxPathObserved: 0,
      );
    }

    // Analyse each contact using the live topology graph.
    int maxHopDist = 0;
    bool anyNeedForwarding = false;
    final forwardPrefixes = <Uint8List>[];
    int directCount = 0;
    int multiHopCount = 0;
    int unknownCount = 0;

    for (final contact in input.contacts) {
      if (contact.publicKey.length < 6) continue;

      // Derive the 12-char lowercase hex prefix from the stored 32-byte key.
      final contactPrefix = contact.publicKey
          .sublist(0, 6)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join()
          .toLowerCase();

      final hopDist = _topology.hopDistance(localPrefix, contactPrefix);

      if (hopDist == null) {
        // Unknown — topology not yet converged or contact never sent a #T:.
        // Conservatively treat as [_unknownHopDefault] hops.
        unknownCount++;
        anyNeedForwarding = true;
        if (maxHopDist < _unknownHopDefault) maxHopDist = _unknownHopDefault;
        forwardPrefixes
            .add(Uint8List.fromList(contact.publicKey.sublist(0, 6)));
      } else if (hopDist == 0) {
        directCount++;
      } else {
        // Multi-hop contact.
        multiHopCount++;
        anyNeedForwarding = true;
        if (hopDist > maxHopDist) maxHopDist = hopDist;
        forwardPrefixes
            .add(Uint8List.fromList(contact.publicKey.sublist(0, 6)));
      }
    }

    if (!anyNeedForwarding) {
      // All tracked contacts are currently direct neighbours.
      if (_currentMaxHops > 0 && !_holdActive) _startHold();
      return ForwardingDecision(
        maxHops: _currentMaxHops,
        prefixes: const [],
        strategyMode: modeKey,
        reason: 'All $directCount contacts direct; '
            'hold-down ${_holdActive ? "active" : "inactive"}',
        needsForwarding: false,
        maxPathObserved: 0,
      );
    }

    // At least one contact requires multi-hop routing.
    _cancelHold();
    _currentMaxHops = maxHopDist.clamp(1, _maxHopsCeiling);

    return ForwardingDecision(
      maxHops: _currentMaxHops,
      prefixes: forwardPrefixes,
      strategyMode: modeKey,
      reason: 'Graph routing: direct=$directCount '
          'multiHop=$multiHopCount unknown=$unknownCount '
          'maxHopDist=$maxHopDist → maxHops=$_currentMaxHops '
          'prefixes=${forwardPrefixes.length}',
      needsForwarding: true,
      maxPathObserved: maxHopDist,
    );
  }

  // ---------------------------------------------------------------------------
  // Hold-down helpers
  // ---------------------------------------------------------------------------

  void _startHold() {
    _holdActive = true;
    _holdTimer?.cancel();
    _holdTimer = Timer(_holdDuration, () {
      _holdActive = false;
      _currentMaxHops = 0;
      debugPrint('[TopologyV2] Hold-down expired — dropping to maxHops=0');
      onStateChanged?.call();
    });
  }

  void _cancelHold() {
    _holdTimer?.cancel();
    _holdTimer = null;
    _holdActive = false;
  }
}
