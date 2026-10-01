import Crypto
import Dependencies
import Dependencies_Test_Support
import OneTimePasswordShared
import Testing

@testable import TOTP

@Suite(

    .dependency(\.date, .init { Fixture.now() })
)
struct Test {

    @Test
    func `RFC 6238 Test Vectors - SHA1`() throws {

        let secret = Array("12345678901234567890".utf8)
        let totp = try TOTP(secret: secret, digits: 8, algorithm: .sha1)

        struct TestVector {
            let time: Double
            let expected: String
        }

        let testVectors = [
            TestVector(time: 59, expected: "94287082"),
            TestVector(time: 1_111_111_109, expected: "07081804"),
            TestVector(time: 1_111_111_111, expected: "14050471"),
            TestVector(time: 1_234_567_890, expected: "89005924"),
            TestVector(time: 2_000_000_000, expected: "69279037"),
            TestVector(time: 20_000_000_000, expected: "65353130"),
        ]

        for vector in testVectors {
            let otp = totp.generate(at: Fixture.date(vector.time))
            #expect(
                otp == vector.expected,
                "SHA1 at time \(vector.time) should be \(vector.expected), got \(otp)"
            )
        }
    }

    @Test
    func `RFC 6238 Test Vectors - SHA256`() throws {

        let secret = Array("12345678901234567890123456789012".utf8)
        let totp = try TOTP(secret: secret, digits: 8, algorithm: .sha256)

        struct TestVector {
            let time: Double
            let expected: String
        }

        let testVectors = [
            TestVector(time: 59, expected: "46119246"),
            TestVector(time: 1_111_111_109, expected: "68084774"),
            TestVector(time: 1_111_111_111, expected: "67062674"),
            TestVector(time: 1_234_567_890, expected: "91819424"),
            TestVector(time: 2_000_000_000, expected: "90698825"),
            TestVector(time: 20_000_000_000, expected: "77737706"),
        ]

        for vector in testVectors {
            let otp = totp.generate(at: Fixture.date(vector.time))
            #expect(
                otp == vector.expected,
                "SHA256 at time \(vector.time) should be \(vector.expected), got \(otp)"
            )
        }
    }

    @Test
    func `RFC 6238 Test Vectors - SHA512`() throws {

        let secret = Array("1234567890123456789012345678901234567890123456789012345678901234".utf8)
        let totp = try TOTP(secret: secret, digits: 8, algorithm: .sha512)

        struct TestVector {
            let time: Double
            let expected: String
        }

        let testVectors = [
            TestVector(time: 59, expected: "90693936"),
            TestVector(time: 1_111_111_109, expected: "25091201"),
            TestVector(time: 1_111_111_111, expected: "99943326"),
            TestVector(time: 1_234_567_890, expected: "93441116"),
            TestVector(time: 2_000_000_000, expected: "38618901"),
            TestVector(time: 20_000_000_000, expected: "47863826"),
        ]

        for vector in testVectors {
            let otp = totp.generate(at: Fixture.date(vector.time))
            #expect(
                otp == vector.expected,
                "SHA512 at time \(vector.time) should be \(vector.expected), got \(otp)"
            )
        }
    }

    @Test
    func `TOTP Generation and Validation`() throws {
        let secret = TOTP.generateSecret()
        let totp = try TOTP.sha1(base32Secret: secret)

        let otp = totp.generate()
        #expect(otp.count == 6, "OTP should be 6 digits")

        #expect(totp.validate(otp), "Current OTP should be valid")

        #expect(!totp.validate("000000"), "Invalid OTP should not validate")
    }

    @Test
    func `TOTP Time Window`() throws {
        let secret = "JBSWY3DPEHPK3PXP"
        let totp = try TOTP.sha1(base32Secret: secret)

        let testTime = Fixture.date(1_234_567_890)
        let otp = totp.generate(at: testTime)

        #expect(totp.validate(otp, at: testTime, window: 0))

        let timeInWindow = Fixture.date(1_234_567_890 + 30)
        #expect(totp.validate(otp, at: timeInWindow, window: 1))

        let timeOutsideWindow = Fixture.date(1_234_567_890 + 90)
        #expect(!totp.validate(otp, at: timeOutsideWindow, window: 1))
    }

    @Test
    func `Secret Generation`() {

        let secret1 = TOTP.generateSecret()
        let data1 = RFC_6238.Base32.decode(secret1)
        #expect(data1 != nil)
        #expect(data1?.count == 20, "Default secret should be 20 bytes")

        let secret2 = TOTP.generateSecret(length: 32)
        let data2 = RFC_6238.Base32.decode(secret2)
        #expect(data2 != nil)
        #expect(data2?.count == 32, "Custom secret should be 32 bytes")

        #expect(secret1 != secret2, "Generated secrets should be unique")
    }

    @Test
    func `Secure Key Generation`() throws {
        let totp = try TOTP.generateNew(algorithm: .sha256, digits: 6)

        #expect(totp.algorithm == .sha256)
        #expect(totp.digits == 6)
        #expect(totp.timeStep == 30)
        #expect(totp.secret.count == 32, "SHA256 should use 32-byte key")

        let otp = totp.generate()
        #expect(otp.count == 6)
    }

    @Test
    func `Factory Methods`() throws {
        let secret = TOTP.generateSecret()

        let sha1TOTP = try TOTP.sha1(base32Secret: secret)
        #expect(sha1TOTP.algorithm == .sha1)
        #expect(sha1TOTP.digits == 6)

        let sha256TOTP = try TOTP.sha256(base32Secret: secret, digits: 8)
        #expect(sha256TOTP.algorithm == .sha256)
        #expect(sha256TOTP.digits == 8)

        let sha512TOTP = try TOTP.sha512(base32Secret: secret)
        #expect(sha512TOTP.algorithm == .sha512)
        #expect(sha512TOTP.digits == 6)
    }

    @Test
    func `Provisioning URI`() throws {
        let secret = "JBSWY3DPEHPK3PXP"
        let totp = try TOTP.sha256(base32Secret: secret, digits: 8)

        let uri = totp.provisioningURI(label: "alice@example.com", issuer: "ACME Corp")

        let url = Fixture.components(of: uri)
        #expect(url != nil)

        #expect(url?.scheme == "otpauth")
        #expect(url?.host == "totp")
        #expect(url?.path == "/alice@example.com")

        let queryItems = url?.queryItems ?? []
        let params = Dictionary(uniqueKeysWithValues: queryItems.map { ($0.name, $0.value ?? "") })

        #expect(params["secret"] == secret)
        #expect(params["algorithm"] == "SHA256")
        #expect(params["digits"] == "8")
        #expect(params["period"] == "30")
        #expect(params["issuer"] == "ACME Corp")
    }

    @Test
    func `Migration Parameters`() throws {
        let originalSecret = TOTP.generateSecret()
        let originalTOTP = try TOTP.sha256(base32Secret: originalSecret, digits: 8)

        let params = originalTOTP.exportMigration(issuer: "TestApp", accountName: "user@test.com")

        #expect(params.secret == originalSecret)
        #expect(params.issuer == "TestApp")
        #expect(params.accountName == "user@test.com")
        #expect(params.algorithm == .sha256)
        #expect(params.digits == 8)
        #expect(params.period == 30)

        let importedTOTP = try TOTP.from(migration: params)

        #expect(importedTOTP.secret == originalTOTP.secret)
        #expect(importedTOTP.algorithm == originalTOTP.algorithm)
        #expect(importedTOTP.digits == originalTOTP.digits)
        #expect(importedTOTP.timeStep == originalTOTP.timeStep)
    }

    @Test
    func `Time Remaining`() throws {
        let totp = try TOTP.generateNew()

        let remaining = totp.timeRemaining()
        #expect(remaining > 0)
        #expect(remaining <= 30)

        let testTime = Fixture.date(1_234_567_890)
        let remainingAtTest = totp.timeRemaining(at: testTime)
        #expect(abs(remainingAtTest - 30) < 0.001)
    }

    @Test
    func `Current OTP Property`() throws {
        let totp = try TOTP.generateNew()
        let otp1 = totp.currentOTP
        let otp2 = totp.generate()

        #expect(otp1 == otp2, "Current OTP should match generate()")

        #expect(totp.validate(otp1))
    }

    @Test
    func `Invalid Base32`() {

        #expect(throws: RFC_6238.Error.invalidBase32String) {
            _ = try TOTP(base32Secret: "INVALID!@#")
        }

        #expect(throws: RFC_6238.Error.emptySecret) {
            _ = try TOTP(base32Secret: "")
        }
    }

    @Test
    func `TOTP Initialization Errors`() {

        #expect(throws: RFC_6238.Error.emptySecret) {
            _ = try TOTP(secret: [UInt8](), digits: 6)
        }

        #expect(throws: RFC_6238.Error.self) {
            _ = try TOTP(secret: [UInt8](repeating: 0x42, count: 20), digits: 5)
        }

        #expect(throws: RFC_6238.Error.self) {
            _ = try TOTP(secret: [UInt8](repeating: 0x42, count: 20), digits: 9)
        }

        #expect(throws: RFC_6238.Error.self) {
            _ = try TOTP(secret: [UInt8](repeating: 0x42, count: 20), timeStep: 0)
        }

        #expect(throws: RFC_6238.Error.self) {
            _ = try TOTP(secret: [UInt8](repeating: 0x42, count: 20), timeStep: -30)
        }
    }

    @Test
    func `Symmetric Key Integration`() throws {
        let key = SymmetricKey(size: .bits256)
        let totp = try TOTP(symmetricKey: key, algorithm: .sha256)

        #expect(totp.algorithm == .sha256)
        #expect(totp.secret.count == 32)

        let otp = totp.generate()
        #expect(otp.count == 6)
        #expect(totp.validate(otp))
    }

    @Test
    func `Base32 Secret Property`() throws {
        let originalSecret = "JBSWY3DPEHPK3PXP"
        let totp = try TOTP.sha1(base32Secret: originalSecret)

        let exportedSecret = totp.base32Secret
        #expect(exportedSecret == originalSecret)

        let totp2 = try TOTP.sha1(base32Secret: exportedSecret)
        #expect(totp.secret == totp2.secret)
    }
}
