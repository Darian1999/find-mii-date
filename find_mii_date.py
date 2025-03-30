#!/usr/bin/env python3

import struct
import datetime
import argparse
import os
import string # For checking hex letters

# --- Constants ---
EXPECTED_FILE_SIZE = 96  # cfsd files are 96 bytes
CHUNK_SIZE = 4         # Analyze 4 bytes (8 hex letters) at a time
MASK = 0x0FFFFFFF      # Mask to ignore the first hex digit (top 4 bits)

# --- Epoch and Multiplier (Wii U / 3DS) ---
# Epoch Jan 1, 2010, increment every 2 seconds
WIIU_3DS_EPOCH = datetime.datetime(2010, 1, 1, 0, 0, 0)
WIIU_3DS_MULTIPLIER = 2
SYSTEM_TYPE_LABEL = "Wii U/3DS (Epoch 2010, x2s)"

# --- Target Date Range (Inclusive) ---
TARGET_START_DATE = datetime.datetime(2011, 1, 1, 0, 0, 0)
# Default end date (end of Dec 31, 2012)
DEFAULT_TARGET_END_DATE = datetime.datetime(2012, 12, 31, 23, 59, 59)
# Extended end date (end of Sep 30, 2013)
EXTENDED_TARGET_END_DATE = datetime.datetime(2013, 9, 30, 23, 59, 59)

# --- Helper Functions ---

def bytes_to_hex(byte_data):
    """Converts bytes to an uppercase hex string."""
    return byte_data.hex().upper()

def contains_hex_letter(hex_string):
    """Checks if a hex string contains at least one letter (A-F)."""
    return any(c in string.hexdigits[10:] for c in hex_string.upper()) # Check A-F

def calculate_date_wiiu_3ds(value):
    """
    Calculates the creation date from a 32-bit value using Wii U/3DS rules.
    Applies the mask. Returns a datetime object or None if calculation fails.
    """
    # Apply the mask to ignore the first hex digit (top 4 bits)
    timestamp_value = value & MASK
    try:
        # Calculate seconds offset from epoch
        seconds_offset = timestamp_value * WIIU_3DS_MULTIPLIER
        # Calculate the final date
        creation_date = WIIU_3DS_EPOCH + datetime.timedelta(seconds=seconds_offset)
        return creation_date
    except (OverflowError, ValueError):
        # Date calculation might fail if value is unexpectedly large or invalid
        return None

# --- Main Analysis Function ---

def analyze_cfsd(filepath, effective_end_date):
    """
    Analyzes a .cfsd file for potential Wii U/3DS Mii creation dates
    within the target range, applying filters.
    Returns a list of dictionaries, each representing a potential match.
    """
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return None # Indicate error
    if not os.path.isfile(filepath):
        print(f"Error: Path is not a file: {filepath}")
        return None # Indicate error

    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except IOError as e:
        print(f"Error reading file {filepath}: {e}")
        return None # Indicate error

    # Validate file size
    if len(data) != EXPECTED_FILE_SIZE:
        print(f"Error: File size is {len(data)} bytes, but expected {EXPECTED_FILE_SIZE} bytes.")
        print("This tool is designed specifically for 96-byte .cfsd files.")
        return None # Indicate error

    found_matches = []
    skipped_no_letter_count = 0
    skipped_date_range_count = 0

    print(f"Analyzing {EXPECTED_FILE_SIZE // CHUNK_SIZE} chunks of {CHUNK_SIZE} bytes (8 hex chars)...")

    for offset in range(0, EXPECTED_FILE_SIZE, CHUNK_SIZE):
        chunk = data[offset : offset + CHUNK_SIZE]
        if len(chunk) < CHUNK_SIZE: continue

        try:
            value = struct.unpack('>I', chunk)[0] # Big-endian unsigned int
        except struct.error:
            print(f"Warning: Could not unpack bytes at offset 0x{offset:02X}")
            continue

        hex_representation = bytes_to_hex(chunk)

        # --- Filter 1: Check for Hex Letters ---
        if not contains_hex_letter(hex_representation):
            skipped_no_letter_count += 1
            # print(f"Debug: Skipping offset 0x{offset:02X} (Hex: {hex_representation}) - no letters.") # Optional debug
            continue # Skip this chunk if it contains only digits 0-9

        # --- Try Wii U / 3DS Calculation ---
        creation_date = calculate_date_wiiu_3ds(value)

        # --- Filter 2: Check Date Range ---
        if creation_date and TARGET_START_DATE <= creation_date <= effective_end_date:
            # This chunk passes both filters
            found_matches.append({
                "offset": offset,
                "hex": hex_representation,
                "date": creation_date,
                "type": SYSTEM_TYPE_LABEL, # Kept for consistency, though only one type now
                "raw_value": value,
                "masked_value": value & MASK
            })
        elif creation_date:
             # Date was calculated but outside the effective range
             skipped_date_range_count += 1
             # print(f"Debug: Skipping offset 0x{offset:02X} (Date: {creation_date.strftime('%Y-%m-%d')}) - outside effective range.") # Optional debug


    if skipped_no_letter_count > 0:
        print(f"Note: Skipped {skipped_no_letter_count} chunk(s) because their hex representation contained no letters (A-F).")
    if skipped_date_range_count > 0:
         print(f"Note: Skipped {skipped_date_range_count} chunk(s) with valid dates outside the effective target range.")


    return found_matches

# --- Command Line Interface ---

def main():
    parser = argparse.ArgumentParser(
        description=f"Analyze a 96-byte .cfsd file (Wii U) to find potential Mii "
                    f"creation dates based on 4-byte chunks representing a Mii ID timestamp "
                    f"({SYSTEM_TYPE_LABEL}). Filters results based on date range and hex content.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(f"Default target date range: {TARGET_START_DATE.strftime('%Y-%m-%d')} to {DEFAULT_TARGET_END_DATE.strftime('%Y-%m-%d')}.\n"
                f"Use --extend to use the range up to {EXTENDED_TARGET_END_DATE.strftime('%Y-%m-%d')}.\n"
                f"Chunks whose 4-byte hex representation contains no letters (A-F) are ignored.\n\n"
                "Example usage:\n"
                "  python mii_date_finder_wiiu.py your_mii_data.cfsd\n"
                "  python mii_date_finder_wiiu.py your_mii_data.cfsd --extend")
    )
    parser.add_argument("filepath", help="Path to the .cfsd file.")
    parser.add_argument(
        "--extend",
        action="store_true",
        help=f"Extend the target end date to {EXTENDED_TARGET_END_DATE.strftime('%Y-%m-%d')} "
             f"(default is {DEFAULT_TARGET_END_DATE.strftime('%Y-%m-%d')})."
    )
    args = parser.parse_args()

    # Determine the effective end date based on the --extend flag
    effective_end_date = EXTENDED_TARGET_END_DATE if args.extend else DEFAULT_TARGET_END_DATE

    print(f"--- Analyzing File: {args.filepath} ---")
    print(f"System Type: {SYSTEM_TYPE_LABEL}")
    print(f"Target Date Range: {TARGET_START_DATE.strftime('%Y-%m-%d')} to {effective_end_date.strftime('%Y-%m-%d')}")
    if args.extend:
        print("(Using extended date range)")
    print("Filtering: Potential IDs must contain at least one hex letter (A-F).")


    results = analyze_cfsd(args.filepath, effective_end_date)

    # Handle cases where analysis failed (e.g., file not found, wrong size)
    if results is None:
        print("-" * 30)
        print("Analysis aborted due to errors.")
        return # Exit script

    # --- Step 1: Report all potential matches ---
    print("-" * 30)
    if not results:
        print("STEP 1: No potential Mii creation dates found matching all criteria.")
    else:
        print(f"STEP 1: Found {len(results)} potential match(es) matching all criteria:")
        # Sort results by file offset for consistent display
        results.sort(key=lambda x: x['offset'])
        for result in results:
            print(f"  - Offset: 0x{result['offset']:02X} | "
                  f"Hex: {result['hex']} | "
                  f"Date: {result['date'].strftime('%Y-%m-%d %H:%M:%S')}")

    # --- Step 2: Suggest the most likely Mii ID based on offset ---
    print("-" * 30)
    if not results:
        print("STEP 2: Cannot determine most likely Mii ID (no potential matches found).")
    else:
        print("STEP 2: Determining Most Likely Mii ID Timestamp Candidate...")

        # Find the minimum offset among all valid results
        min_offset = min(r['offset'] for r in results)

        # Filter results to include only the one at the minimum offset
        likely_match = next((r for r in results if r['offset'] == min_offset), None)

        print(f"Heuristic Used: Mii ID timestamps are often located near the start of Mii data.")
        print(f"The candidate at the lowest found offset (0x{min_offset:02X}) is considered most likely:\n")

        if likely_match:
             print(f"  - Offset: 0x{likely_match['offset']:02X}")
             print(f"    Hex Value: {likely_match['hex']}")
             print(f"    Calculated Date: {likely_match['date'].strftime('%Y-%m-%d %H:%M:%S')}")
             # Optional: Show raw/masked values for debugging/info
             # print(f"    Raw Int Value: {likely_match['raw_value']} (0x{likely_match['raw_value']:X})")
             # print(f"    Masked Int Value (used for calc): {likely_match['masked_value']} (0x{likely_match['masked_value']:X})")
        else:
             # This case should technically not happen if results is not empty
             print("  Error: Could not find the match at the minimum identified offset.")


    print("--- Analysis Complete ---")


if __name__ == "__main__":
    main()
