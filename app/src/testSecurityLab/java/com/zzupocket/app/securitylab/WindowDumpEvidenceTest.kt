package com.zzupocket.app.securitylab

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WindowDumpEvidenceTest {
    private val expected = WindowDumpIdentity("ZZUPocketOfflineDialog-1234-100", 2,
        "com.zzupocket.app.secure.securitylab", 10123)

    private fun window(
        title: String = expected.title,
        owner: String = expected.ownerPackage,
        uid: Int = expected.ownerUid,
        type: String = "APPLICATION",
        flags: String = "USE_BLAST HIDE_NON_SYSTEM_OVERLAY_WINDOWS",
        number: Int = 0,
    ): String = """
  Window #$number Window{a1b2 u0 $title}:
    mDisplayId=0 rootTaskId=1
    mOwnerUid=$uid showForAllUsers=false package=$owner appop=NONE
    mAttrs={(0,0)(fillxfill) gr=CENTER sim={adjust=RESIZE} ty=$type fmt=TRANSPARENT
      fl=HARDWARE_ACCELERATED SECURE
      pfl=$flags
      bhv=DEFAULT}
    mHasSurface=true
""".trimIndent()

    @Test
    fun matchesActualDialogTitleOwnerUidAndApplicationAttributes() {
        assertTrue(WindowDumpEvidence.confirmsHiddenOverlays(window(), expected))
        assertTrue(WindowDumpEvidence.confirmsHiddenOverlays(window(type = "2"), expected))
    }

    @Test
    fun flagOnAnotherWindowCannotProtectTargetDialog() {
        val dump = window(flags = "USE_BLAST") + "\n" +
            window(title = "DifferentWindow", owner = "other.package", uid = 10999, number = 1)
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(dump, expected))
    }

    @Test
    fun globalFocusFooterCannotCombineTargetPackageWithAnotherWindowFlag() {
        val dump = window(title = "OtherWindow", owner = "other.package", uid = 10999) + """

  mCurrentFocus=Window{ffff u0 ZZUPocketOfflineDialog-1234-100}
  mFocusedApp=ActivityRecord{bbbb com.zzupocket.app.secure.securitylab/OfflineHarnessActivity}
"""
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(dump, expected))
    }

    @Test
    fun globalFlagAfterTargetAttributesIsIgnored() {
        val dump = window(flags = "USE_BLAST") + """

  mCurrentFocus=Window{ffff u0 ZZUPocketOfflineDialog-1234-100}
  package=com.zzupocket.app.secure.securitylab HIDE_NON_SYSTEM_OVERLAY_WINDOWS
"""
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(dump, expected))
    }

    @Test
    fun wrongOwnerPackageOrUidIsRejectedEvenWhenTitleMatches() {
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(window(owner = "other.package"), expected))
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(window(uid = 10999), expected))
    }

    @Test
    fun baseApplicationPanelAndWrongExpectedRootTypeAreRejected() {
        for (type in listOf("BASE_APPLICATION", "APPLICATION_PANEL", "1", "1000")) {
            assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(window(type = type), expected))
        }
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(window(), expected.copy(type = 1)))
    }

    @Test
    fun missingPrivateFlagOrFlagInDifferentAttributeIsRejected() {
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(window(flags = "USE_BLAST"), expected))
        val wrongField = window(flags = "USE_BLAST").replace("fl=HARDWARE_ACCELERATED SECURE",
            "fl=HARDWARE_ACCELERATED SECURE HIDE_NON_SYSTEM_OVERLAY_WINDOWS")
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(wrongField, expected))
    }

    @Test
    fun duplicateTitlesAndPrefixMatchesAreNotUnambiguousEvidence() {
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(window() + "\n" + window(number = 1), expected))
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(window(title = expected.title + "-another"), expected))
    }

    @Test
    fun truncatedAttributeRecordCannotBorrowFlagFromGlobalFooter() {
        val dump = window(flags = "USE_BLAST").substringBefore("bhv=DEFAULT}") + """

  mCurrentFocus=Window{ffff u0 ZZUPocketOfflineDialog-1234-100}
  pfl=HIDE_NON_SYSTEM_OVERLAY_WINDOWS
"""
        assertFalse(WindowDumpEvidence.confirmsHiddenOverlays(dump, expected))
    }
}
