// Driver of the Swift goal runner. Build: swiftc -O GoalReplay.swift main.swift -o goal-runner ; run: ./goal-runner <vectors-dir>
import Foundation

let (count, probes, bad) = try goalReplay(CommandLine.arguments[1])
print("swift: \(count) vectors, \(probes) probes, \(bad.count) disagreements")
for b in bad.prefix(20) { print("   " + b) }
exit(bad.isEmpty && count > 0 ? 0 : 1)
