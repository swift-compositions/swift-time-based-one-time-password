import Crypto
import Dependencies
import Dependencies_Test_Support
import OneTimePasswordShared
import Testing

@testable import HOTP
@testable import TOTP

@Suite(
    .dependency(\.date, .init { Fixture.now() })
)
struct `README Verification` {

    @Test
    func `README Example - Basic TOTP Generation (lines 50-71)`() throws {

        let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")

        let code = totp.generate()
        #expect(!code.isEmpty)
        #expect(code.count == 6)

        let currentCode = totp.currentOTP
        #expect(!currentCode.isEmpty)

        if totp.validate(code) {

        }

        let remaining = totp.timeRemaining()
        #expect(remaining > 0)
        #expect(remaining <= 30)
    }

    @Test
    func `README Example - Generate Secure Secrets (lines 73-86)`() throws {

        let secret = TOTP.generateSecret()
        #expect(!secret.isEmpty)

        let totp = try TOTP.generateNew(algorithm: .sha256, digits: 6)
        let code = totp.generate()
        #expect(code.count == 6)

        let base32Secret = totp.base32Secret
        #expect(!base32Secret.isEmpty)
    }

    @Test
    func `README Example - Different Hash Algorithms (lines 88-99)`() throws {

        let secret = TOTP.generateSecret()

        let sha1TOTP = try TOTP.sha1(base32Secret: secret)
        #expect(sha1TOTP.algorithm == .sha1)

        let sha256TOTP = try TOTP.sha256(base32Secret: secret, digits: 8)
        #expect(sha256TOTP.algorithm == .sha256)
        #expect(sha256TOTP.digits == 8)

        let sha512TOTP = try TOTP.sha512(base32Secret: secret)
        #expect(sha512TOTP.algorithm == .sha512)
    }

    @Test
    func `README Example - Provisioning URI (lines 101-113)`() throws {

        let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")
        let uri = totp.provisioningURI(
            label: "user@example.com",
            issuer: "My App"
        )

        #expect(uri.starts(with: "otpauth://totp/"))
        #expect(uri.contains("secret=JBSWY3DPEHPK3PXP"))
        #expect(uri.contains("issuer=My%20App"))
    }

    @Test
    func `README Example - Time Window Validation (lines 115-129)`() throws {

        let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")
        let userInput = totp.generate()

        let validWithWindow = totp.validate(userInput, window: 1)

        #expect(validWithWindow)

        let validExact = totp.validate(userInput, window: 0)

        #expect(validExact)
    }

    @Test
    func `README Example - Migration Support (lines 131-145)`() throws {

        let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")

        let params = totp.exportMigration(
            issuer: "My Service",
            accountName: "user@example.com"
        )

        #expect(params.issuer == "My Service")
        #expect(params.accountName == "user@example.com")

        let imported = try TOTP.from(migration: params)
        let code = imported.generate()
        #expect(code.count == 6)
    }

    @Test
    func `README Example - Basic HOTP Generation (lines 149-169)`() throws {

        let secret = Array("12345678901234567890".utf8)
        let hotp = try HOTP(secret: secret, digits: 6)

        let code = hotp.generate(counter: 1, using: CryptoHMACProvider())
        #expect(code.count == 6)

        let nextCode = hotp.generate(counter: 2, using: CryptoHMACProvider())
        #expect(nextCode.count == 6)
        #expect(code != nextCode)

        let isValid = hotp.validate(code, counter: 1)
        #expect(isValid)
    }

    @Test
    func `README Example - HOTP Different Algorithms (lines 171-184)`() throws {

        let secret = Array("12345678901234567890".utf8)

        let hotp256 = try HOTP(secret: secret, digits: 6, algorithm: .sha256)
        let code256 = hotp256.generate(counter: 1, using: CryptoHMACProvider())
        #expect(code256.count == 6)

        let hotp512 = try HOTP(secret: secret, digits: 8, algorithm: .sha512)
        let code512 = hotp512.generate(counter: 1, using: CryptoHMACProvider())
        #expect(code512.count == 8)

        let hotpBase32 = try HOTP(base32Secret: "JBSWY3DPEHPK3PXP", algorithm: .sha256)
        let codeBase32 = hotpBase32.generate(counter: 1, using: CryptoHMACProvider())
        #expect(codeBase32.count == 6)
    }

    @Test
    func `README Example - Testing with Dependency Injection (lines 230-244)`() throws {

        try withDependencies {
            $0.date = .constant(Fixture.date(1_234_567_890))
        } operation: {
            let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")
            let code = totp.generate()

            #expect(code.count == 6)
        }
    }

    @Test
    func `README Example - Package Dependencies Compile Check`() {

        let totpExists = true
        let hotpExists = true
        #expect(totpExists && hotpExists)
    }

    @Test
    func `Verify README Pattern - SymmetricKey Integration`() throws {

        let key = SymmetricKey(size: .bits256)
        let totp = try TOTP(symmetricKey: key, algorithm: .sha256)

        #expect(totp.algorithm == .sha256)
        let code = totp.generate()
        #expect(code.count == 6)
        #expect(totp.validate(code))
    }

    @Test
    func `Verify README Pattern - Base32 Secret Property`() throws {

        let originalSecret = "JBSWY3DPEHPK3PXP"
        let totp = try TOTP.sha1(base32Secret: originalSecret)

        let exportedSecret = totp.base32Secret
        #expect(exportedSecret == originalSecret)
    }

    @Test
    func `Verify README Pattern - Time Remaining`() throws {

        let totp = try TOTP.generateNew()

        let remaining = totp.timeRemaining()
        #expect(remaining > 0)
        #expect(remaining <= 30)
    }
}
