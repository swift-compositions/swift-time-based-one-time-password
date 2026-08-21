import Foundation

extension Date {

    public struct Generator: Sendable {
        private let generate: @Sendable () -> Date

        public init(_ generate: @escaping @Sendable () -> Date) {
            self.generate = generate
        }

        public func callAsFunction() -> Date {
            generate()
        }
    }
}

extension Date.Generator {

    public static func constant(_ date: Date) -> Self {
        Self { date }
    }
}
