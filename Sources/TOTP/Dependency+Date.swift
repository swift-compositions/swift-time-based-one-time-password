import Dependencies
import Foundation

private enum DateKey: Dependency.Key {}

extension DateKey {
    static var liveValue: Date.Generator {
        Date.Generator { Date() }
    }
}

extension __DependencyValues {

    public var date: Date.Generator {
        get { self[DateKey.self] }
        set { self[DateKey.self] = newValue }
    }
}
