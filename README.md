# Wii U Mii ID Timestamp Finder for .CFSD Files

## What is This?

This Python script is a specialized tool designed to analyze 96-byte `.cfsd` files, commonly associated with the Wii U filesystem. Its primary goal is to identify potential 4-byte sequences within the file that could represent a Wii U/3DS-format Mii ID timestamp. It specifically looks for timestamps that correspond to a creation date between **January 1st, 2011** and **December 25th, 2012**, inclusive.

The tool operates in two steps:
1.  **Scan & Filter:** It reads every 4-byte chunk in the file, interprets it as a potential timestamp using the Wii U/3DS Mii ID rules, and lists all chunks that result in a date within the target range.
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
2.  **Chunk Iteration:** Reads the file and iterates through it in 4-byte chunks (from offset 0x00, 0x04, 0x08... up to 0x5C).
3.  **Value Interpretation:** Each 4-byte chunk is interpreted as a **32-bit unsigned integer in Big-Endian** byte order (`>I` in Python's `struct` module). Big-endian is common for such data in Nintendo systems.
4.  **Timestamp Calculation:**
    *   The raw integer value is bitwise-ANDed with `0x0FFFFFFF` to apply the mask.
    *   The masked value is multiplied by `2` (the seconds multiplier).
    *   This result (total seconds offset) is added to the `2010-01-01 00:00:00` epoch datetime object.
5.  **Date Range Check:** The calculated `datetime` object is compared against the target start (`2011-01-01 00:00:00`) and end (`2012-12-25 23:59:59`) dates.
6.  **Reporting (Step 1):** If the calculated date falls within the range, the file offset, the original hex value of the chunk, and the calculated date/time are stored and later printed.
7.  **Heuristic Analysis (Step 2):** After scanning the entire file, the tool finds the minimum offset among all successful matches. The match corresponding to this minimum offset is presented as the most likely candidate.

## Requirements

*   **Python 3.x**
*   Standard libraries only (`os`, `sys`, `struct`, `datetime`, `argparse`). No external packages need to be installed.

## Usage

Run the script from your terminal, providing the path to the `.cfsd` file as the only argument.

```bash
python mii_date_finder_wiiu.py <path_to_your_file.cfsd>
