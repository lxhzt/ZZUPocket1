package com.zzupocket.app.core.security

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** A failed local read must not terminate the listener that revokes old academic UI. */
suspend fun runAcademicRead(onFailure: (Exception) -> Unit, read: suspend () -> Unit) {
    try {
        read()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (error: Exception) {
        currentCoroutineContext().ensureActive()
        onFailure(error)
    }
}
