// prompt.h — hidden password entry for non-TUI (CLI subcommand) flows.
// Reads a line from the terminal with echo disabled, into a SecureBuffer.
// Never reads from argv/env (agenda §14.9). Callers check stdin_is_tty()
// first (the CLI refuses to run without a terminal). An empty line, or EOF,
// gives an empty buffer (size 0). Echo comes back however the prompt ends,
// also on Ctrl+C or a hangup while it waits.
#ifndef SECRAXIS_PROMPT_H
#define SECRAXIS_PROMPT_H

#include "secraxis/secure_buffer.h"

namespace secraxis {

SecureBuffer read_hidden_line(const char* prompt);
bool stdin_is_tty();

}  // namespace secraxis

#endif  // SECRAXIS_PROMPT_H
