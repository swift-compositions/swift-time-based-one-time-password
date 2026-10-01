import Foundation

enum Fixture {
    static func date(_ secondsSince1970: Double) -> Date {
        Date(timeIntervalSince1970: secondsSince1970)
    }

    static func now() -> Date {
        Date()
    }
}

extension Fixture {
    struct Components {
        let scheme: String?
        let host: String?
        let path: String
        let queryItems: [(name: String, value: String?)]
    }

    static func components(of uri: String) -> Components? {
        URLComponents(string: uri).map { url in
            Components(
                scheme: url.scheme,
                host: url.host,
                path: url.path,
                queryItems: (url.queryItems ?? []).map { (name: $0.name, value: $0.value) }
            )
        }
    }
}
