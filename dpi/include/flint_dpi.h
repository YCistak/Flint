#ifndef FLINT_DPI_H
#define FLINT_DPI_H

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Return codes for dpi_start() and dpi_stop()
 * ---------------------------------------------------------------------- */
#define DPI_OK                  0
#define DPI_ERR_ALREADY_RUNNING (-1)
#define DPI_ERR_NOT_RUNNING     (-2)

/* -------------------------------------------------------------------------
 * Status values returned by dpi_status()
 * ---------------------------------------------------------------------- */
#define DPI_STATUS_STOPPED  0
#define DPI_STATUS_RUNNING  1
#define DPI_STATUS_ERROR    2

/* -------------------------------------------------------------------------
 * API
 * ---------------------------------------------------------------------- */

/**
 * dpi_start — start the DPI bypass engine in a background thread.
 *
 * On Linux the engine opens nfqueue 0.  The caller must have set up an
 * iptables rule to divert traffic before calling this function:
 *
 *   iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
 *
 * Returns DPI_OK (0) on success, DPI_ERR_ALREADY_RUNNING if the engine
 * is already running.
 */
int dpi_start(void);

/**
 * dpi_stop — stop the DPI bypass engine.
 *
 * Signals the background thread to exit and releases resources.
 * Returns DPI_OK (0) on success, DPI_ERR_NOT_RUNNING if the engine
 * was not running.
 */
int dpi_stop(void);

/**
 * dpi_status — return the current engine status.
 *
 * Returns one of DPI_STATUS_STOPPED, DPI_STATUS_RUNNING, DPI_STATUS_ERROR.
 */
int dpi_status(void);

#ifdef __cplusplus
}
#endif

#endif /* FLINT_DPI_H */
