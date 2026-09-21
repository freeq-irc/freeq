import XCTest
@testable import FreeqMacosCore

/// The signature mark a message row wears for each verdict, and when a row
/// that would group starts its own header because of it.
final class RowSignatureMarkTests: XCTestCase {

    private func verdict(_ kind: VerdictKind, _ layer: VerdictLayer? = nil) -> VerdictInfo {
        VerdictInfo(kind: kind, layer: layer, sentence: "the sentence the SDK gave")
    }

    func testAPublishedDeviceKeyWearsTheLockAtFullStrength() {
        XCTAssertEqual(RowSignatureMark.of(verdict(.device, .published)), .lock(opacity: 1))
    }

    func testAVouchedDeviceKeyWearsTheLockAt30Percent() {
        XCTAssertEqual(RowSignatureMark.of(verdict(.device, .vouched)), .lock(opacity: 0.3))
    }

    func testAFailedOrRetiredSignatureWearsTheWarning() {
        XCTAssertEqual(RowSignatureMark.of(verdict(.invalid)), .warning)
        XCTAssertEqual(RowSignatureMark.of(verdict(.retired)), .warning)
    }

    func testEveryOtherStateAndNoVerdictWearNothing() {
        for kind in [VerdictKind.server, .unsigned, .unverifiable, .pending] {
            XCTAssertNil(RowSignatureMark.of(verdict(kind)), "\(kind) must not mark the row")
        }
        XCTAssertNil(RowSignatureMark.of(nil))
    }

    // MARK: - Grouping by the row mark

    private func startsHeader(_ header: VerdictInfo?, _ row: VerdictInfo?) -> Bool {
        RowSignatureMark.startsHeader(
            header: RowSignatureMark.settled(header), row: RowSignatureMark.settled(row))
    }

    func testARowWithTheSameMarkAsItsHeaderGroups() {
        XCTAssertFalse(startsHeader(verdict(.device, .published), verdict(.device, .published)))
    }

    func testFullLockThenDimLockStartsAHeader() {
        XCTAssertTrue(startsHeader(verdict(.device, .published), verdict(.device, .vouched)))
    }

    func testLockThenWarningStartsAHeader() {
        XCTAssertTrue(startsHeader(verdict(.device, .published), verdict(.invalid)))
    }

    func testLockThenNoMarkStartsAHeader() {
        XCTAssertTrue(startsHeader(verdict(.device, .published), verdict(.server)))
    }

    func testARowWhoseCheckIsPendingGroups() {
        XCTAssertFalse(startsHeader(verdict(.device, .published), verdict(.pending)))
        XCTAssertFalse(startsHeader(verdict(.device, .published), nil))
    }

    func testAPendingRowStartsAHeaderWhenItsVerdictSettlesDifferent() {
        XCTAssertFalse(startsHeader(verdict(.device, .published), verdict(.pending)))
        XCTAssertTrue(startsHeader(verdict(.device, .published), verdict(.invalid)))
    }

    func testAPendingRowStaysGroupedWhenItsVerdictSettlesTheSame() {
        XCTAssertFalse(startsHeader(verdict(.device, .published), verdict(.pending)))
        XCTAssertFalse(startsHeader(verdict(.device, .published), verdict(.device, .published)))
    }

    func testTheSettledMarkIsNilOnlyWhilePendingOrWithNoVerdict() {
        XCTAssertNil(RowSignatureMark.settled(verdict(.pending)))
        XCTAssertNil(RowSignatureMark.settled(nil))
        XCTAssertEqual(RowSignatureMark.settled(verdict(.server)), RowSignatureMark.Settled(mark: nil))
        XCTAssertEqual(RowSignatureMark.settled(verdict(.invalid)), RowSignatureMark.Settled(mark: .warning))
    }
}
