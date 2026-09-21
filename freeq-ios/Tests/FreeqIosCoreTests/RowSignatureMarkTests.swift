import XCTest
@testable import FreeqIosCore

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

    // MARK: - Headers for a whole transcript

    private let full = RowSignatureMark.Settled(mark: .lock(opacity: 1))
    private let dim = RowSignatureMark.Settled(mark: .lock(opacity: 0.3))

    func testARunStartsANewHeaderAtEachMarkChangeAndAtEachBreak() {
        XCTAssertEqual(
            RowSignatureMark.headers(
                breaksRun: [true, false, false, false, false, true, false],
                marks: [full, full, dim, dim, full, full, full]),
            [true, false, true, false, true, true, false])
    }

    func testPendingRowsGroupUnderTheHeaderAndDoNotMoveIt() {
        XCTAssertEqual(
            RowSignatureMark.headers(breaksRun: [true, false, false, false], marks: [full, nil, full, dim]),
            [true, false, false, true])
    }

    /// The rule as the list used to apply it, row by row: walk back to the run's
    /// first row, then forward, moving the header at each row that starts one.
    private func headerByWalkingTheRun(_ breaksRun: [Bool], _ marks: [RowSignatureMark.Settled?], _ idx: Int) -> Bool {
        if breaksRun[idx] { return true }
        var start = idx - 1
        while !breaksRun[start] { start -= 1 }
        var headerMark = marks[start]
        for j in (start + 1)...idx {
            guard RowSignatureMark.startsHeader(header: headerMark, row: marks[j]) else { continue }
            if j == idx { return true }
            headerMark = marks[j]
        }
        return false
    }

    func testOnePassMatchesWalkingTheRunForEveryShortTranscript() {
        let values: [RowSignatureMark.Settled?] = [nil, RowSignatureMark.Settled(mark: nil), full, dim]
        for count in 1...6 {
            for breakBits in 0..<(1 << (count - 1)) {
                let breaksRun = [true] + (1..<count).map { breakBits & (1 << ($0 - 1)) != 0 }
                var digits = [Int](repeating: 0, count: count)
                repeat {
                    let marks = digits.map { values[$0] }
                    let expected = (0..<count).map { headerByWalkingTheRun(breaksRun, marks, $0) }
                    XCTAssertEqual(RowSignatureMark.headers(breaksRun: breaksRun, marks: marks), expected)
                    var k = 0
                    while k < count { digits[k] += 1; if digits[k] < values.count { break }; digits[k] = 0; k += 1 }
                    if k == count { break }
                } while true
            }
        }
    }
}
