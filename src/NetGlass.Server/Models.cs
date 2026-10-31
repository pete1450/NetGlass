using System.Text.Json.Serialization;

namespace NetGlass.Server;

public sealed record AgentInfo(
    string Id, string Name, string Hostname, string Os, string Version,
    string Token, DateTime LastSeen, int SocketCount);

public sealed record ConnectionDto(
    string AgentId, string AgentName,
    string Direction, string Proto, string State,
    string Local, string Remote, string RemoteHost,
    int? Pid, string Process, string Exe, string Cmdline, string User,
    int? Ppid, string Parent, string ParentExe,
    string Unit, string Container, string ContainerId,
    DateTime? Started, DateTime FirstSeen, DateTime LastSeen,
    bool IsGhost, bool IsNew, bool Suspicious, string[] Flags);

public sealed record SnapshotConnection(
    string Direction, string Proto, string State,
    string Local, string Remote,
    int? Pid, string Process, string Exe, string Cmdline, string User,
    int? Ppid, string Parent, string ParentExe,
    string Unit, string Container, string ContainerId,
    DateTime? Started);

public sealed record SnapshotRequest(
    string Hostname, string Os, string Version,
    List<SnapshotConnection> Connections);

public sealed record KillRequestDto(
    string Id, string AgentId, int Pid, string Exe, DateTime? Started,
    string Reason, string Status, DateTime CreatedAt, string? Result);

public sealed record AlertRuleDto(
    string Id, string Name, string Type, string Pattern,
    int Threshold, int WindowMinutes, bool Enabled);

public sealed record RecordingDto(
    string Id, string Name, DateTime StartedAt, DateTime? EndedAt, int EventCount);

public sealed record RecordingEventDto(
    long Seq, DateTime At, string EventType, string AgentName,
    string Direction, string Process, string Exe, string Local, string Remote);
