# Define variables for escape sequences using the string command
string(ASCII 7   BEL)
string(ASCII 8   BS)
string(ASCII 9   HT)
string(ASCII 10  LF)
string(ASCII 11  VT)
string(ASCII 12  FF)
string(ASCII 13  CR)
string(ASCII 27  ESC)
string(ASCII 92  SLASH)
string(ASCII 127 DEL)

# https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797

set(ANSI_ESC                  "${SLASH}033")

# Predeficed sequences
set(ANSI_HOME                 "${ESC}[H")
set(ANSI_GET_CURSOR_POS       "${ESC}[6n")
set(ANSI_SAVE_CURSOR_POS      "${ESC}[s")
set(ANSI_RESTORE_CURSOR_POS   "${ESC}[u")
set(ANSI_ERASE_END_DISPLAY    "${ESC}[0J")
set(ANSI_ERASE_START_DISPLAY  "${ESC}[1J")
set(ANSI_ERASE_FULL_DISPLAY   "${ESC}[2J")
set(ANSI_ERASE_SAVED_DISPLAY  "${ESC}[3J")
set(ANSI_ERASE_END_LINE       "${ESC}[0K")
set(ANSI_ERASE_START_LINE     "${ESC}[1K")
set(ANSI_ERASE_FULL_LINE      "${ESC}[2K")

# Variable sequences
set(ANSI_CURSOR_UP            "${ESC}[1A") # ESC[#A where # is number of columns
set(ANSI_CURSOR_DOWN          "${ESC}[1B")
set(ANSI_CURSOR_RIGHT         "${ESC}[1C")
set(ANSI_CURSOR_LEFT          "${ESC}[1D")
set(ANSI_CURSOR_NEW_LINE      "${ESC}[1E")
set(ANSI_CURSOR_PREV_LINE     "${ESC}[1F")
set(ANSI_CURSOR_GO_COLUMN     "${ESC}[1G")

# Graphic modes
set(ANSI_RESET_MODE           "${ESC}[0m")
set(ANSI_SET_BOLD_MODE        "${ESC}[1m")
set(ANSI_UNSET_BOLD_MODE      "${ESC}[21m")
set(ANSI_SET_DIM_MODE         "${ESC}[2m")
set(ANSI_UNSET_DIM_MODE       "${ESC}[22m")
set(ANSI_SET_ITALIC_MODE      "${ESC}[3m")
set(ANSI_UNSET_ITALIC_MODE    "${ESC}[23m")
set(ANSI_SET_UNDERLINE_MODE   "${ESC}[4m")
set(ANSI_UNSET_UNDERLINE_MODE "${ESC}[24m")
set(ANSI_SET_BLINKING_MODE    "${ESC}[5m")
set(ANSI_UNSET_BLINKING_MODE  "${ESC}[25m")
set(ANSI_SET_INVERSE_MODE     "${ESC}[7m")
set(ANSI_UNSET_INVERSE_MODE   "${ESC}[27m")
set(ANSI_SET_HIDDEN_MODE      "${ESC}[8m")
set(ANSI_UNSET_HIDDEN_MODE    "${ESC}[28m")
set(ANSI_SET_STRIKEOUT_MODE   "${ESC}[9m")
set(ANSI_UNSET_STRIKEOUT_MODE "${ESC}[29m")

# Colors
# ESC[38;2;{r};{g};{b}m 	Set foreground color as RGB.
# ESC[48;2;{r};{g};{b}m 	Set background color as RGB.

set(ANSI_ENABLE_PRINT_MODE     "${ESC}[5i")
set(ANSI_DISABLE_PRINT_MODE    "${ESC}[4i")

set(LAST_FRAME_WIDTH 0)

# Function to get terminal width
function(get_terminal_width RETURN_VALUE)
    execute_process(
        COMMAND bash -c "echo -en \"\\E[999C\\E[6n\" > /dev/tty &&
                         read -sdR CURPOS < /dev/tty &&
                         CURPOS=\${CURPOS#*[} &&
                         COL=\${CURPOS#*;} &&
                         echo \$COL"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        RESULT_VARIABLE RESULT
        OUTPUT_VARIABLE OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    message(" ")

    set(${RETURN_VALUE} "${OUTPUT}" PARENT_SCOPE)
endfunction()

function(calculate_line_width CONTENTS RETURN_VALUE)
    execute_process(
        COMMAND bash -c "
        echo \"${CONTENTS}\" | awk '{
            gsub(/\\x1b\[[0-9;]*m/, \"\");
            if (length > max_length) max_length = length
        } END { print max_length }'
        "
        OUTPUT_VARIABLE OUTPUT
        ERROR_QUIET
    )

    set(${RETURN_VALUE} "${OUTPUT}" PARENT_SCOPE)
endfunction()

function(calculate_left_offset TERMINAL_WIDTH LINE_WIDTH RETURN_VALUE)
    math(EXPR OFFSET "(${TERMINAL_WIDTH} - ${LINE_WIDTH}) / 2")
    set(${RETURN_VALUE} "${OFFSET}" PARENT_SCOPE)
endfunction()

function(draw_animation_frame ANSI_FILE)
    get_terminal_width(TERMINAL_WIDTH)

    if(NOT LAST_FRAME_WIDTH EQUAL TERMINAL_WIDTH)
        set(LAST_FRAME_WIDTH ${TERMINAL_WIDTH} PARENT_SCOPE)
        message("${ANSI_ERASE_FULL_DISPLAY}")
    endif()
    message("${ANSI_HOME}${ANSI_DISPLAY_MM_MODE}")

    file(READ ${ANSI_FILE} CONTENTS)
    execute_process(
        COMMAND bash -c "
        while IFS= read -r line; do
            echo -e \"\$line\"
        done <<< \"${CONTENTS}\""
        OUTPUT_VARIABLE RESULT
        ERROR_QUIET
    )

    set(TEXT_TOP "You like compiling C++")
    calculate_line_width("${TEXT_TOP}" TEXT_TOP_WIDTH)
    calculate_left_offset(${TERMINAL_WIDTH} ${TEXT_TOP_WIDTH} TEXT_TOP_LEFT_OFFSET)
    message("${ANSI_CURSOR_LEFT}${ANSI_CURSOR_UP}${ESC}[${TEXT_TOP_LEFT_OFFSET}C${TEXT_TOP}")

    set(TEXT_BOTTOM "don't you?")
    calculate_line_width("${TEXT_BOTTOM}" TEXT_BOTTOM_WIDTH)
    calculate_left_offset(${TERMINAL_WIDTH} ${TEXT_BOTTOM_WIDTH} TEXT_BOTTOM_LEFT_OFFSET)
    message("${ESC}[${TEXT_BOTTOM_LEFT_OFFSET}C${TEXT_BOTTOM}")

    calculate_line_width("${RESULT}" IMAGE_WIDTH)
    calculate_left_offset(${TERMINAL_WIDTH} ${IMAGE_WIDTH} IMAGE_LEFT_OFFSET)
    execute_process(
        COMMAND bash -c "
        while IFS= read -r line; do
            echo -e \"${ESC}[${IMAGE_LEFT_OFFSET}C\$line\"
        done <<< \"${RESULT}\""
        OUTPUT_VARIABLE RESULT
        ERROR_QUIET
    )
    message("${RESULT}")

endfunction()

function(draw_animation REPEAT DELAY)
    set(ANSI_FILES_DIR "${CMAKE_SOURCE_DIR}/cmake/utils/animation")
    file(GLOB ANSI_FILES "${ANSI_FILES_DIR}/*.ansi")

    if(NOT DELAY)
        set(DELAY 0.5)
    endif()

    if(NOT REPEAT)
        set(REPEAT 1)
    endif()
    message("${ANSI_ERASE_FULL_DISPLAY}")

    math(EXPR REPEAT_COUNT "${REPEAT} - 1")
    while(REPEAT_COUNT GREATER_EQUAL 0)
        foreach(ANSI_FILE ${ANSI_FILES})
            draw_animation_frame(${ANSI_FILE})
            execute_process(COMMAND sleep ${DELAY})
        endforeach()

        math(EXPR REPEAT_COUNT "${REPEAT_COUNT} - 1")
    endwhile()
endfunction()

execute_process(COMMAND sleep 1)
draw_animation(3 0.1)
message("${ANSI_ERASE_FULL_DISPLAY}${ANSI_HOME}${ANSI_DISPLAY_MM_MODE}")

