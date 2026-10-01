import Dependencies
import Dependencies_Test_Support
import OneTimePasswordShared
import TOTP
import Testing

private let rfc6238SecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

private let rfc6238SHA1Vectors: [(time: Double, expected: String)] = [
    (59, "94287082"),
    (1_111_111_109, "07081804"),
    (1_111_111_111, "14050471"),
    (1_234_567_890, "89005924"),
    (2_000_000_000, "69279037"),
    (20_000_000_000, "65353130"),
]

@Suite
struct `TOTP Clock Tests` {

    @Suite
    struct Unit {

        @Test
        func `Overridden date dependency drives generate()`() throws {
            let totp = try TOTP(base32Secret: rfc6238SecretBase32, digits: 8, algorithm: .sha1)
            for vector in rfc6238SHA1Vectors {
                let fixed = Fixture.date(vector.time)
                withDependencies {
                    $0.date = .init { fixed }
                } operation: {

                    #expect(totp.generate() == vector.expected)
                    #expect(totp.generate() == totp.generate(at: fixed))
                }
            }
        }

        @Test
        func `Counter matches the RFC 6238 Appendix B time steps`() throws {
            let totp = try TOTP(base32Secret: rfc6238SecretBase32, digits: 8, algorithm: .sha1)
            #expect(totp.counter(at: 59) == 1)
            #expect(totp.counter(at: 1_111_111_109) == 37_037_036)
            #expect(totp.counter(at: 1_111_111_111) == 37_037_037)
            #expect(totp.counter(at: 1_234_567_890) == 41_152_263)
            #expect(totp.counter(at: 2_000_000_000) == 66_666_666)
            #expect(totp.counter(at: 20_000_000_000) == 666_666_666)
        }

        @Test
        func `Code is constant within one time step`() throws {
            let totp = try TOTP(base32Secret: rfc6238SecretBase32, digits: 8, algorithm: .sha1)

            for time: Double in [30, 45, 59] {
                #expect(totp.generate(at: Fixture.date(time)) == "94287082")
            }
        }

        @Test
        func `Time remaining counts down to the step boundary`() throws {
            let totp = try TOTP(base32Secret: rfc6238SecretBase32, digits: 8, algorithm: .sha1)
            #expect(totp.timeRemaining(at: Fixture.date(59)) == 1)
            #expect(totp.timeRemaining(at: Fixture.date(60)) == 30)
        }
    }

    @Suite
    struct `Edge Case` {

        @Test
        func `Code changes across a time-step boundary`() throws {
            let totp = try TOTP(base32Secret: rfc6238SecretBase32, digits: 8, algorithm: .sha1)
            #expect(totp.counter(at: 59) == 1)
            #expect(totp.counter(at: 60) == 2)
            #expect(totp.generate(at: Fixture.date(60)) != "94287082")
        }

        @Test
        func `Timezone-offset timestamps land whole steps away`() throws {

            let totp = try TOTP(base32Secret: rfc6238SecretBase32, digits: 8, algorithm: .sha1)
            let time: Double = 1_111_111_109
            #expect(totp.counter(at: time + 7200) == totp.counter(at: time) + 240)
            #expect(totp.generate(at: Fixture.date(time + 7200)) != "07081804")
        }
    }

    @Suite
    struct Integration {

        @Test
        func `Base32 secret initialization matches the RFC 6238 SHA1 vectors`() throws {
            let totp = try TOTP(base32Secret: rfc6238SecretBase32, digits: 8, algorithm: .sha1)
            for vector in rfc6238SHA1Vectors {
                let code = totp.generate(at: Fixture.date(vector.time))
                #expect(
                    code == vector.expected,
                    "at \(vector.time) expected \(vector.expected), got \(code)"
                )
            }
        }

        @Test
        func `Six-digit codes truncate the eight-digit RFC vectors`() throws {
            let eightDigit = try TOTP(
                base32Secret: rfc6238SecretBase32,
                digits: 8,
                algorithm: .sha1
            )
            let sixDigit = try TOTP(base32Secret: rfc6238SecretBase32, digits: 6, algorithm: .sha1)
            for vector in rfc6238SHA1Vectors {
                let date = Fixture.date(vector.time)
                let code = sixDigit.generate(at: date)
                #expect(code == String(vector.expected.suffix(6)))
                #expect(code == String(eightDigit.generate(at: date).suffix(6)))
            }
        }
    }
}
