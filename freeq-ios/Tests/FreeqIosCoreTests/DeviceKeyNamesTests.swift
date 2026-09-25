import XCTest
@testable import FreeqIosCore

/// The Keychain names each account's device key is kept under. The store
/// itself needs the Keychain and the generated bindings.
final class DeviceKeyNamesTests: XCTestCase {

    private func all(_ names: DeviceKeyNames) -> [String] {
        [names.seed, names.createdAt, names.recordUri, names.refused]
    }

    func testTwoAccountsGetDifferentNames() {
        let alice = all(DeviceKeyNames(did: "did:plc:alice"))
        let bob = all(DeviceKeyNames(did: "did:plc:bob"))
        XCTAssertTrue(Set(alice).isDisjoint(with: bob), "\(alice) \(bob)")
        XCTAssertEqual(Set(alice).count, 4, "four distinct names")
    }

    func testOneAccountGetsTheSameNamesEachTime() {
        XCTAssertEqual(DeviceKeyNames(did: "did:plc:alice"), DeviceKeyNames(did: "did:plc:alice"))
    }

    func testTheOldSharedNamesAreTheOnesDeletedAndNoAccountUsesThem() {
        XCTAssertEqual(
            DeviceKeyNames.legacy,
            ["deviceKeySeed", "deviceKeyCreatedAt", "deviceKeyRecordUri", "deviceKeyRefused"])
        XCTAssertTrue(Set(all(DeviceKeyNames(did: "did:plc:alice"))).isDisjoint(with: DeviceKeyNames.legacy))
    }
}
