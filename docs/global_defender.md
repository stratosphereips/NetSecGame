# Global Defender

!!! note
    The global defender, available in previous environment versions, will not be supported in the future. To enable backward compatibility, the global defender functionality can be enabled by adding `use_global_defender: True` to the configuration YAML file in the `env` section. This option is disabled by default.

The global defender is a stochastic (non-agentic) detection system that simulates a SIEM. It monitors agent actions and probabilistically detects suspicious behavior patterns.

## How Detection Works

All actions are analyzed in **time windows (TW)** of 5 actions (by default). Every new action slides the window by one position. The defender evaluates whether the latest action should trigger a detection based on three types of thresholds.

## Detection Thresholds

### Detection Probabilities

Each action type has a base probability of being detected. However, detection only triggers if additional behavioral patterns are met (see below).

| Action Type | Detection Probability |
|---|---|
| ScanNetwork | 0.05 |
| FindServices | 0.075 |
| ExploitService | 0.1 |
| FindData | 0.025 |
| ExfiltrateData | 0.025 |
| BlockIP | 0.01 |

For example, a single `ScanNetwork` action has a 5% probability of being detected.

### Type Ratio Threshold

Defines how frequently an action must appear in the time window to be considered for detection. If the ratio is below the threshold, no detection occurs.

**Example:** If the last action is `ScanNetwork` in a TW of `[ScanNetwork, FindService, ScanNetwork, FindData, ScanNetwork]`, the ratio is 3/5 = 0.6.

| Action Type | Ratio Threshold |
|---|---|
| ScanNetwork | 0.25 |
| FindServices | 0.3 |
| ExploitService | 0.25 |
| FindData | 0.5 |
| ExfiltrateData | 0.25 |
| BlockIP | 1 |

### Consecutive Actions Threshold

Determines the maximum number of consecutive occurrences of an action type within the time window before detection is triggered.

| Action Type | Consecutive Threshold |
|---|---|
| ScanNetwork | 2 |
| FindServices | 3 |
| ExfiltrateData | 2 |

### Repeated Action Threshold

Applies to certain action types and defines the number of times a specific action must appear in the **entire episode** before it can be considered for detection.

| Action Type | Repeated Threshold |
|---|---|
| ExploitService | 2 |
| FindData | 2 |

## Decision Logic

The system monitors actions and maintains a history of recent ones within the time window:

1. If an action's **Type Ratio Threshold** is met within the time window **or** it exceeds the **Consecutive Actions Threshold**, it is evaluated for detection.
2. If the action type has a **Repeated Action Threshold** and has not been repeated enough times in the episode, it is ignored.
3. If an action meets the conditions above, it is subject to detection based on its predefined **Detection Probability**.
4. Actions that do not meet any threshold conditions are ignored, ensuring that occasional activity does not lead to unnecessary detections.

This approach ensures that only repeated or excessive behavior is flagged, reducing false positives while maintaining a realistic monitoring system.

## API Reference

::: netsecgame.game.global_defender
