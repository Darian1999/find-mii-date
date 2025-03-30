# Wii U Mii ID Timestamp Finder for .CFSD Files

## What is This?

This Python script is a specialized tool designed to analyze 96-byte `.cfsd` files, commonly associated with the Wii U filesystem. Its primary goal is to identify potential 4-byte sequences within the file that could represent a Wii U/3DS-format Mii ID timestamp.

It specifically looks for timestamps that correspond to a creation date between **January 1st, 2011** and **December 31st, 2012** (inclusive) by default. An option (`--extend`) exists to extend the target end date to **September 30th, 2013**.

The tool operates in two steps:
1.  **Scan & Filter:** It reads every 4-byte chunk in the file. It first checks if the chunk's hexadecimal representation contains at least one letter (A-F); chunks with only digits (0-9) are skipped. For valid chunks, it interprets them as potential timestamps using the Wii U/3DS Mii ID rules and lists all chunks that result in a date within the selected target range.
2.  **Heuristic Guess:** Based on the common placement of Mii ID data near the beginning of Mii data structures, it highlights the match found at the lowest file offset as the most probable candidate for the *actual* Mii ID timestamp within that `.cfsd` file.

## The Nerd Details: Mii ID Timestamps (Wii U / 3DS Format)

Unlike the randomly generated UUIDs used for Switch Miis, Nintendo implemented a deterministic timestamp-based system for Mii IDs on the Wii and later the Wii U / 3DS platforms. This was likely done to drastically reduce the probability of ID collisions across the millions of consoles.

The Wii U / 3DS Mii ID timestamp follows these rules:

*   **Epoch:** The clock starts counting from **January 1st, 2010, 00:00:00**. (Note: This is based on the console's system time when the Mii was created, so timezone locality applies).
*   **Resolution:** The counter increments by 1 every **2 seconds**.
*   **Storage:** The core timestamp value is derived from a 32-bit integer field within the Mii data.
*   **Masking:** Crucially, the **top 4 bits** (equivalent to the first hexadecimal digit) of this 32-bit field are **ignored** when calculating the timestamp. This means we apply a bitmask of `0x0FFFFFFF` to the raw 32-bit value before using it in calculations. The purpose of these top 4 bits varies but they are not part of the sequential time counter.

Therefore, to reverse the process:
`Seconds Since Epoch = (Raw_32bit_Value & 0x0FFFFFFF) * 2`
`Creation Date = Epoch_DateTime + TimeDelta(seconds = Seconds Since Epoch)`

## How the Tool Works

1.  **File Validation:** Checks if the provided file exists, is a regular file, and is exactly 96 bytes long. Aborts if not.
2.  **Argument Parsing:** Checks if the `--extend` flag was provided to determine the target end date.
3.  **Chunk Iteration:** Reads the file and iterates through it in 4-byte chunks (from offset 0x00, 0x04, 0x08... up to 0x5C).
4.  **Value Interpretation:** Each 4-byte chunk is interpreted as a **32-bit unsigned integer in Big-Endian** byte order (`>I` in Python's `struct` module). Big-endian is common for such data in Nintendo systems.
5.  **Hex Content Check:** The 8-character hexadecimal representation of the chunk is checked. If it contains *only* numerical digits (0-9) and no letters (A-F), the chunk is skipped, and the tool moves to the next chunk.
6.  **Timestamp Calculation:**
    *   The raw integer value is bitwise-ANDed with `0x0FFFFFFF` to apply the mask.
    *   The masked value is multiplied by `2` (the seconds multiplier).
    *   This result (total seconds offset) is added to the `2010-01-01 00:00:00` epoch datetime object.
7.  **Date Range Check:** The calculated `datetime` object is compared against the target start date (`2011-01-01 00:00:00`) and the *effective* end date (either `2012-12-31 23:59:59` by default, or `2013-09-30 23:59:59` if the `--extend` flag is used).
8.  **Reporting (Step 1):** If the chunk passed the hex content check *and* the calculated date falls within the effective range, the file offset, the original hex value of the chunk, and the calculated date/time are stored and later printed.
9.  **Heuristic Analysis (Step 2):** After scanning the entire file, the tool finds the minimum offset among all successful matches. The match corresponding to this minimum offset is presented as the most likely candidate.

## Requirements

*   **Python 3.x**
*   Standard libraries only (`os`, `struct`, `datetime`, `argparse`, `string`). No external packages need to be installed.

## Usage

Run the script from your terminal, providing the path to the `.cfsd` file. Use the optional `--extend` flag to search within the later date range.

```bash
# Default date range (ends Dec 31, 2012)
# Ignores hex values without letters (A-F)
python mii_date_finder_wiiu.py <path_to_your_file.cfsd>

# Extended date range (ends Sep 30, 2013)
# Ignores hex values without letters (A-F)
python mii_date_finder_wiiu.py <path_to_your_file.cfsd> --extend
``` 

