"""Data staging template — heap buffer for egghunter retrieval.

Generates a global heap buffer and handle_data_staging() function that
stores received data persistently in memory. The attacker can send
shellcode (prefixed with an egg tag) via the staging command, then use
an egghunter to locate it on the heap.
"""

from target_builder.src.config import ServerConfig


def generate_data_staging_function(config: ServerConfig) -> str:
    """Generate C++ globals and handle_data_staging() function.

    The function allocates a persistent heap buffer on first call and
    copies received data into it. The buffer is never freed, so the
    data remains in the process address space for an egghunter to find.
    """
    if not config.data_staging:
        return ""

    return """\
// Data staging — persistent heap buffer for received data
static char* g_staging_buf = NULL;
static int g_staging_offset = 0;
#define STAGING_BUF_SIZE 65536

void handle_data_staging(char* data, int data_len) {
    if (g_staging_buf == NULL) {
        g_staging_buf = (char*)malloc(STAGING_BUF_SIZE);
        if (g_staging_buf == NULL) return;
        memset(g_staging_buf, 0, STAGING_BUF_SIZE);
    }

    if (g_staging_offset + data_len > STAGING_BUF_SIZE) {
        // Wrap around — overwrite from start
        g_staging_offset = 0;
    }

    memcpy(g_staging_buf + g_staging_offset, data, data_len);
    g_staging_offset += data_len;
}
"""
