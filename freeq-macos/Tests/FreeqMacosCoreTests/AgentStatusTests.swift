import XCTest
@testable import FreeqMacosCore

final class AgentStatusTests: XCTestCase {
    let raw = "project=phoenix-agent doing=answering+chad-bot-phoenix+in+#phoenix+·+0s"

    func testDecodesKeyValueStatus() {
        let s = AgentStatus.parse(raw)
        XCTAssertEqual(s?.project, "phoenix-agent")
        XCTAssertEqual(s?.doing, "answering chad-bot-phoenix in #phoenix")
        XCTAssertNil(s?.state)
    }

    func testTakesStateOffAwayReason() {
        let s = AgentStatus.parse("executing: \(raw) model=opus branch=main")
        XCTAssertEqual(s?.state, "executing")
        XCTAssertEqual(s?.model, "opus")
        XCTAssertEqual(s?.context, "phoenix-agent @main · opus")
        XCTAssertEqual(s?.summary, "Working · answering chad-bot-phoenix in #phoenix")
    }

    func testLeavesPeopleAlone() {
        XCTAssertNil(AgentStatus.parse("out to lunch"))
        XCTAssertNil(AgentStatus.parse("back at 3: see you"))
        XCTAssertNil(AgentStatus.parse("{\"status\":\"lunch\"}"))
        XCTAssertNil(AgentStatus.parse("a=b c=d"))
        XCTAssertNil(AgentStatus.parse(""))
        XCTAssertNil(AgentStatus.parse(nil))
        XCTAssertEqual(AgentStatus.displayAway("lunch"), "lunch")
        XCTAssertEqual(AgentStatus.displayAway("executing: project=x"), "Working · x")
    }

    func testActivityLabelIsDecoded() {
        var m = MemberInfo(nick: "bot", isOp: false, isHalfop: false, isVoiced: false, awayMsg: nil, did: nil)
        m.actorClass = "agent"
        m.presenceStatus = raw
        XCTAssertEqual(m.activityLabel, "answering chad-bot-phoenix in #phoenix")
        m.presenceStatus = "project=p"
        m.presenceState = "executing"
        XCTAssertEqual(m.activityLabel, "working")
    }

    /// "· 0s" was the age when an older agent sent it, and stayed on screen
    /// for minutes. Dropped; a "·" inside the phrase is not.
    func testDropsTheFrozenElapsedCount() {
        XCTAssertEqual(AgentStatus.parse("doing=answering+chad+·+12m")?.doing, "answering chad")
        XCTAssertEqual(AgentStatus.parse("doing=fixing+the+·+separator")?.doing, "fixing the · separator")
    }

    func testReadsWhenTheWorkBegan() {
        let s = AgentStatus.parse("doing=answering+chad since=1790769600")
        XCTAssertEqual(s?.since, Date(timeIntervalSince1970: 1_790_769_600))
        XCTAssertNil(AgentStatus.parse("doing=x since=soon")?.since)
    }

    func testElapsedCountsFromSince() {
        let t0 = Date(timeIntervalSince1970: 1_790_769_600)
        XCTAssertEqual(AgentStatus.elapsed(since: t0, now: t0.addingTimeInterval(5)), "5s")
        XCTAssertEqual(AgentStatus.elapsed(since: t0, now: t0.addingTimeInterval(190)), "3m")
        XCTAssertEqual(AgentStatus.elapsed(since: t0, now: t0.addingTimeInterval(7200)), "2h")
        XCTAssertEqual(AgentStatus.elapsed(since: t0.addingTimeInterval(4), now: t0), "0s")
    }

    func testFactsDoNotRepeatTheProject() {
        let a = AgentStatus.parse("project=writing repo=github.com/chad/writing branch=main")!
        XCTAssertEqual(a.facts.map { $0.0 }, ["Repo", "Branch"])
        let b = AgentStatus.parse("project=site repo=github.com/chad/chadfowler.com model=opus")!
        XCTAssertEqual(b.facts.map { $0.0 }, ["Project", "Repo", "Model"])
    }

    func testReadsStageAndLatestAction() {
        let s = AgentStatus.parse("doing=answering+chad+in+#x step=Running+the+tests tool=bash:+npm+test")
        XCTAssertEqual(s?.doing, "answering chad in #x")
        XCTAssertEqual(s?.step, "Running the tests")
        XCTAssertEqual(s?.tool, "bash: npm test")
        var m = MemberInfo(nick: "bot", isOp: false, isHalfop: false, isVoiced: false, awayMsg: nil, did: nil)
        m.actorClass = "agent"
        m.presenceStatus = "doing=answering+chad step=Running+the+tests"
        // The row shows what moves.
        XCTAssertEqual(m.activityLabel, "Running the tests")
    }
}
