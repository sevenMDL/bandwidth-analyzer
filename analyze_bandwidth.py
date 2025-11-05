#!/usr/bin/env python3
"""
Bandwidth Analyzer Pro - Professional Edition
Author: AI Assistant  
Description: Professional tool for analyzing router bandwidth usage with enhanced reset detection and comprehensive analytics
Version: 2.2 - Enhanced Analytics & Aggregation
"""

import os
import re
import sys
import argparse
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, List
import numpy as np
import pytz

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================
LOG_DIR = "bandwidth"
INTERFACE = "ppp0"
CHART_DIR = os.path.join(LOG_DIR, "charts")
EXPORT_DIR = os.path.join(LOG_DIR, "exports")
WRAP_32 = 2**32  # 32-bit counter wrap detection
CACHE_FILE = ".bandwidth_analyzer_cache"  # Cache file in current directory
RESET_THRESHOLD = 0.8  # 80% drop threshold for reset detection
DEFAULT_TIMEZONE = "Africa/Cairo"

# Usage classification thresholds
USAGE_CLASSIFICATION = {
    "LIGHT": {"max_gb": 10, "color": '\033[92m'},  # GREEN
    "MODERATE": {"max_gb": 20, "color": '\033[93m'},  # YELLOW
    "HEAVY": {"max_gb": float('inf'), "color": '\033[91m'}  # RED
}

# =============================================================================
# COLOR SCHEME FOR PROFESSIONAL OUTPUT
# =============================================================================
class Colors:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

# =============================================================================
# CACHE MANAGEMENT FUNCTIONS
# =============================================================================
def load_cached_args():
    """
    Load cached arguments from file.
    
    Returns:
        Dictionary of cached arguments or empty dict if no cache exists
    """
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                cached_args = json.load(f)
            print_status(f"Loaded cached arguments from {CACHE_FILE}", "INFO")
            return cached_args
    except (json.JSONDecodeError, IOError) as e:
        print_status(f"Cache file corrupted or unreadable: {e}", "WARNING")
    
    return {}

def save_args_to_cache(args_dict):
    """
    Save current arguments to cache file.
    
    Args:
        args_dict: Dictionary of arguments to cache
    """
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(args_dict, f, indent=2)
        
        print_status(f"Arguments cached to {CACHE_FILE}", "SUCCESS")
        
    except Exception as e:
        print_status(f"Failed to save cache: {e}", "WARNING")

def setup_arg_parser():
    """
    Setup argument parser with comprehensive argument definitions.
    
    Returns:
        Configured argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description="Bandwidth Analyzer Pro - Professional network traffic analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --interface ppp0 --details --timezone Africa/Cairo
  %(prog)s --chart --export --alert-gb 100 --peak-analysis
  %(prog)s --log-dir ./bandwidth/ --aggregate hourly daily --stability-report
        """
    )
    
    # Network interface argument
    parser.add_argument("--interface", default=INTERFACE,
                       help=f"Network interface to analyze (default: {INTERFACE})")
    
    # Log directory argument  
    parser.add_argument("--log-dir", default=LOG_DIR,
                       help=f"Directory containing bandwidth snapshots (default: {LOG_DIR})")
    
    # Boolean flags
    parser.add_argument("--chart", action="store_true",
                       help="Generate professional bandwidth chart")
    
    parser.add_argument("--details", action="store_true", 
                       help="Show detailed interval breakdown")
    
    # Optional string argument (can be flag or have value)
    parser.add_argument("--export", nargs='?', const=True, default=False,
                       help="Export to CSV (optionally provide filename or directory)")
    
    # Numeric argument
    parser.add_argument("--alert-gb", type=float,
                       help="Trigger alert if total usage exceeds specified GB")
    
    # New argument for reset detection sensitivity
    parser.add_argument("--reset-threshold", type=float, default=RESET_THRESHOLD,
                       help=f"Reset detection sensitivity (0.0-1.0, default: {RESET_THRESHOLD})")
    
    # NEW ARGUMENTS FOR ENHANCED FEATURES
    parser.add_argument("--timezone", default=DEFAULT_TIMEZONE,
                       help=f"Timezone for analysis (default: {DEFAULT_TIMEZONE})")
    
    parser.add_argument("--aggregate", nargs='+', choices=['hourly', 'daily', 'both'],
                       help="Generate hourly/daily aggregation reports")
    
    parser.add_argument("--peak-analysis", action="store_true",
                       help="Perform peak usage detection and analysis")
    
    parser.add_argument("--stability-report", action="store_true",
                       help="Generate connection stability and reset frequency report")
    
    parser.add_argument("--anomaly-detection", action="store_true",
                       help="Enable traffic anomaly detection")
    
    return parser

def merge_args_with_cache(parser, cached_args):
    """
    Merge cached arguments with command line arguments.
    """
    # Get CLI arguments that were actually provided by user
    provided_dests = set()
    args_list = sys.argv[1:]
    
    i = 0
    while i < len(args_list):
        arg = args_list[i]
        if arg.startswith('--'):
            arg_name = arg.lstrip('-').split('=')[0]
            
            # Find the actual dest name for this argument
            action = next((a for a in parser._actions if f'--{arg_name}' in a.option_strings), None)
            if action and action.dest:
                provided_dests.add(action.dest)
                
                # Skip next token if this argument takes a value
                if action.nargs in [None, '?'] and i + 1 < len(args_list) and not args_list[i + 1].startswith('--'):
                    i += 1
        i += 1

    # Parse CLI args to get ALL current values
    cli_args = parser.parse_args()
    cli_dict = vars(cli_args)
    
    # Get default values
    default_args = {action.dest: action.default for action in parser._actions 
                   if action.dest != 'help'}
    
    # If NO arguments provided, use cached values (preserve cache)
    if not provided_dests:
        # Use cached args if available, otherwise defaults
        final_args = cached_args.copy()
        # Fill any missing keys with defaults
        for key, default_value in default_args.items():
            if key not in final_args:
                final_args[key] = default_value
        return argparse.Namespace(**final_args), cached_args  # Preserve existing cache
    
    # If SOME arguments provided: use provided args + cached defaults, update cache
    else:
        # Start with cached args (or defaults if no cache)
        new_cache = cached_args.copy() if cached_args else default_args.copy()
        
        # Override with provided CLI args
        for key in provided_dests:
            if key in cli_dict:
                new_cache[key] = cli_dict[key]
        
        # Fill any missing keys with defaults
        for key, default_value in default_args.items():
            if key not in new_cache:
                new_cache[key] = default_value
                
        return argparse.Namespace(**new_cache), new_cache

# =============================================================================
# TIMEZONE MANAGEMENT
# =============================================================================
def setup_timezone(timezone_str: str = DEFAULT_TIMEZONE):
    """
    Setup timezone for all datetime operations
    
    Args:
        timezone_str: Timezone string (e.g., 'Africa/Cairo', 'US/Eastern')
    
    Returns:
        timezone object
    """
    try:
        return pytz.timezone(timezone_str)
    except pytz.UnknownTimeZoneError:
        print_status(f"Unknown timezone: {timezone_str}, using UTC", "WARNING")
        return pytz.UTC

def convert_to_local_time(dt: datetime, timezone) -> datetime:
    """
    Convert naive datetime to timezone-aware datetime in local time
    
    Args:
        dt: Naive datetime (assumed UTC)
        timezone: Target timezone
    
    Returns:
        Timezone-aware datetime
    """
    if dt.tzinfo is None:
        dt = pytz.UTC.localize(dt)
    return dt.astimezone(timezone)

# =============================================================================
# BANNER AND DISPLAY UTILITIES
# =============================================================================
def print_banner():
    """Display professional banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                  📊 BANDWIDTH ANALYZER PRO - ENHANCED EDITION               ║
║                                                                              ║
║         Comprehensive Network Analytics with Peak Detection & Reporting      ║
║                    Version 2.2 | Advanced Aggregation                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)

def print_section(title):
    """Print section header with professional styling"""
    visible_len = len(re.sub(r'\033\[[0-9;]*m', '', title))
    width = visible_len + 4

    top_bottom = f"┌{'─' * width}┐"
    middle = f"│  {title}  │"
    middle = middle[:width + 2]

    print(f"\n{Colors.BLUE}{Colors.BOLD}{top_bottom}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}{middle}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}└{'─' * width}┘{Colors.RESET}")

def print_status(message, status="INFO"):
    """Print status messages with colored prefixes"""
    status_colors = {
        "INFO": Colors.BLUE,
        "SUCCESS": Colors.GREEN,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED,
        "PROCESS": Colors.CYAN,
        "RESET": Colors.RED + Colors.BOLD
    }
    color = status_colors.get(status, Colors.WHITE)
    prefix = f"{color}{status:<8}{Colors.RESET}"
    print(f"  {prefix} {message}")

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Display progress bar for processing"""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '░' * (length - filled_length)
    print(f'\r  {Colors.CYAN}PROGRESS {Colors.RESET} │{bar}│ {percent}% {suffix}', end='\r')
    if iteration == total:
        print()

def print_usage_progress_bar(current_gb: float, threshold_gb: float, length: int = 30):
    """
    Display a progress bar showing usage relative to alert threshold
    
    Args:
        current_gb: Current usage in GB
        threshold_gb: Alert threshold in GB
        length: Progress bar length
    """
    if threshold_gb <= 0:
        return
        
    percentage = min(current_gb / threshold_gb, 1.0)
    filled_length = int(length * percentage)
    bar = '█' * filled_length + '░' * (length - filled_length)
    
    # Color coding based on usage level
    if percentage >= 0.9:
        color = Colors.RED
    elif percentage >= 0.7:
        color = Colors.YELLOW
    else:
        color = Colors.GREEN
        
    print(f"  {Colors.WHITE}Usage vs Threshold:{Colors.RESET}")
    print(f"  {color}{bar}{Colors.RESET} {current_gb:.1f} / {threshold_gb:.1f} GB ({percentage*100:.1f}%)")

# =============================================================================
# ENHANCED RESET DETECTION FUNCTIONS
# =============================================================================
def detect_counter_reset(prev_rx: int, curr_rx: int, prev_tx: int, curr_tx: int, threshold: float = RESET_THRESHOLD) -> bool:
    """
    Enhanced counter reset detection by checking for sudden large decreases in values.
    This catches router reboots, interface resets, and counter resets.
    
    Args:
        prev_rx: Previous RX bytes value
        curr_rx: Current RX bytes value
        prev_tx: Previous TX bytes value  
        curr_tx: Current TX bytes value
        threshold: Percentage drop threshold (0.0-1.0) to consider as reset
        
    Returns:
        True if reset detected, False otherwise
    """
    if prev_rx == 0 or prev_tx == 0:  # No previous data to compare
        return False
    
    # Calculate drop ratios for both RX and TX
    rx_drop_ratio = (prev_rx - curr_rx) / prev_rx if prev_rx > 0 else 0
    tx_drop_ratio = (prev_tx - curr_tx) / prev_tx if prev_tx > 0 else 0
    
    # If both counters dropped significantly (more than threshold), it's a reset
    # Also check that current values are reasonable (not negative)
    if (rx_drop_ratio > threshold and tx_drop_ratio > threshold and 
        curr_rx >= 0 and curr_tx >= 0):
        return True
        
    return False

def detect_anomalous_spike(prev_rx: int, curr_rx: int, prev_tx: int, curr_tx: int, 
                          max_reasonable_increase: float = 100.0) -> bool:
    """
    Detect anomalous spikes that might indicate corrupted data.
    
    Args:
        prev_rx: Previous RX bytes
        curr_rx: Current RX bytes
        prev_tx: Previous TX bytes
        curr_tx: Current TX bytes
        max_reasonable_increase: Maximum reasonable increase factor (default 100x)
        
    Returns:
        True if anomalous spike detected
    """
    if prev_rx == 0 or prev_tx == 0:
        return False
    
    rx_increase = curr_rx / prev_rx if prev_rx > 0 else 0
    tx_increase = curr_tx / prev_tx if prev_tx > 0 else 0
    
    # If either counter increased by an unreasonable amount, it's likely corrupted
    if rx_increase > max_reasonable_increase or tx_increase > max_reasonable_increase:
        return True
        
    return False

# =============================================================================
# CORE PARSING FUNCTIONS
# =============================================================================
def parse_snapshot(file_path: str, interface: str) -> Tuple[Optional[datetime], Optional[int], Optional[int]]:
    """
    Extract RX/TX bytes and timestamp from bandwidth snapshot file.
    
    Args:
        file_path: Path to the snapshot file
        interface: Network interface to analyze
        
    Returns:
        Tuple of (timestamp, rx_bytes, tx_bytes) or (None, None, None) on error
    """
    try:
        with open(file_path, "r") as f:
            content = f.read()

        # Extract timestamp from filename (last timestamp in pattern)
        ts_match = re.findall(r"(\d{8}_\d{6})", os.path.basename(file_path))
        if not ts_match:
            return None, None, None
            
        timestamp = datetime.strptime(ts_match[-1], "%Y%m%d_%H%M%S")

        # Parse bandwidth data for specific interface
        for line in content.splitlines():
            if line.strip().startswith(interface + ":"):
                # Use standard /proc/net/dev format parsing
                iface, data = line.split(":", 1)
                parts = re.split(r"\s+", data.strip())
                
                if len(parts) >= 9:
                    rx_bytes = int(parts[0])  # RX bytes at index 0
                    tx_bytes = int(parts[8])  # TX bytes at index 8
                    return timestamp, rx_bytes, tx_bytes
                    
    except (ValueError, IndexError, IOError) as e:
        print_status(f"Error parsing {file_path}: {str(e)}", "WARNING")
        
    return None, None, None

def analyze_bandwidth(log_dir: str, interface: str, reset_threshold: float = RESET_THRESHOLD) -> Tuple[Optional[pd.DataFrame], Dict[str, int]]:
    """
    Enhanced bandwidth usage analysis with advanced reset detection.
    
    Args:
        log_dir: Directory containing bandwidth snapshots
        interface: Network interface to analyze
        reset_threshold: Sensitivity for reset detection
        
    Returns:
        Tuple of (DataFrame with analysis results, dictionary of event counts)
    """
    # Find and sort snapshot files
    files = sorted(
        [os.path.join(log_dir, f) for f in os.listdir(log_dir) 
         if f.startswith("bandwidth_snapshot_")]
    )
    
    if len(files) < 2:
        print_status("Not enough snapshots to analyze (minimum 2 required)", "ERROR")
        return None, {"reset_events": 0, "wrap_events": 0, "anomalies": 0}

    print_status(f"Found {len(files)} snapshot files for processing", "INFO")
    print_status(f"Reset detection threshold: {reset_threshold*100}%", "INFO")
    
    records = []
    reset_events = wrap_events = anomalies = 0

    # Parse first snapshot to initialize
    prev_ts, prev_rx, prev_tx = parse_snapshot(files[0], interface)
    if prev_ts is None or prev_rx is None:
        print_status("Could not parse initial snapshot", "ERROR")
        return None, {"reset_events": 0, "wrap_events": 0, "anomalies": 0}

    # Process subsequent snapshots
    for i, path in enumerate(files[1:]):
        print_progress_bar(i + 1, len(files[1:]), 
                         suffix=f'Processing {os.path.basename(path)}')
        ts, curr_rx, curr_tx = parse_snapshot(path, interface)
        if ts is None or curr_rx is None:
            continue

        delta_t = (ts - prev_ts).total_seconds()
        if delta_t <= 0:
            continue

        # Enhanced counter analysis with reset detection
        reset_detected = False
        anomaly_detected = False
        
        # Check for anomalous spikes first (corrupted data)
        if detect_anomalous_spike(prev_rx, curr_rx, prev_tx, curr_tx):
            print_status(f"📈 Anomalous spike detected in {os.path.basename(path)} - data may be corrupted", "WARNING")
            anomaly_detected = True
            anomalies += 1
            # Skip this interval as data is likely corrupted
            prev_ts, prev_rx, prev_tx = ts, curr_rx, curr_tx
            continue
        
        # Check for counter resets (router reboots, interface resets)
        if detect_counter_reset(prev_rx, curr_rx, prev_tx, curr_tx, reset_threshold):
            rx_diff = curr_rx
            tx_diff = curr_tx
            reset_events += 1
            reset_detected = True
            print_status(f"🔴 COUNTER RESET detected: {format_size(prev_rx/(1024**2))} → {format_size(curr_rx/(1024**2))} "
                        f"(drop: {((prev_rx - curr_rx)/prev_rx*100):.1f}%)", "RESET")
        
        # Handle normal cases and counter wraps
        elif curr_rx >= prev_rx:
            rx_diff = curr_rx - prev_rx
        elif prev_rx < WRAP_32 and curr_rx < WRAP_32:
            rx_diff = (WRAP_32 - prev_rx) + curr_rx
            wrap_events += 1
            print_status(f"🔄 Counter wrap detected for RX in {os.path.basename(path)}", "INFO")
        else:
            rx_diff = curr_rx
            reset_events += 1
            reset_detected = True

        # Apply same logic to TX counter
        if not reset_detected:
            if curr_tx >= prev_tx:
                tx_diff = curr_tx - prev_tx
            elif prev_tx < WRAP_32 and curr_tx < WRAP_32:
                tx_diff = (WRAP_32 - prev_tx) + curr_tx
                wrap_events += 1
            else:
                tx_diff = curr_tx
                if not reset_detected:  # Only count if not already counted for RX
                    reset_events += 1
                    reset_detected = True

        # Calculate rates and store interval data
        if delta_t > 0:
            records.append({
                "start": prev_ts,
                "end": ts,
                "duration_s": delta_t,
                "rx_bytes": rx_diff,
                "tx_bytes": tx_diff,
                "reset_event": reset_detected,
                "anomaly": anomaly_detected
            })
        
        prev_ts, prev_rx, prev_tx = ts, curr_rx, curr_tx

    if files[1:]:
        print()  # New line after progress bar

    if not records:
        print_status("No valid intervals computed from snapshots", "ERROR")
        return None, {"reset_events": reset_events, "wrap_events": wrap_events, "anomalies": anomalies}
        
    # Create DataFrame with enhanced metrics
    print_status("Computing bandwidth metrics...", "PROCESS")
    df = pd.DataFrame(records)
    df["rx_mb"] = df["rx_bytes"] / (1024**2)
    df["tx_mb"] = df["tx_bytes"] / (1024**2)
    df["total_mb"] = df["rx_mb"] + df["tx_mb"]
    df["rate_kbps"] = (df["total_mb"] * 1024 * 8) / df["duration_s"]  # Convert to kbps

    print_status(f"Successfully analyzed {len(df)} intervals", "SUCCESS")
    return df, {"reset_events": reset_events, "wrap_events": wrap_events, "anomalies": anomalies}

# =============================================================================
# AGGREGATION AND ANALYTICS FUNCTIONS
# =============================================================================
def aggregate_hourly_data(df: pd.DataFrame, timezone) -> pd.DataFrame:
    """
    Aggregate data into hourly buckets with timezone support
    
    Args:
        df: DataFrame with bandwidth data
        timezone: Timezone for aggregation
    
    Returns:
        DataFrame with hourly aggregates
    """
    print_status("Computing hourly aggregates...", "PROCESS")
    
    # Make a copy and convert to local timezone
    df_local = df.copy()
    df_local['hour_start'] = df_local['end'].apply(
        lambda x: convert_to_local_time(x, timezone).replace(minute=0, second=0, microsecond=0)
    )
    
    # Group by hour
    hourly = df_local.groupby('hour_start').agg({
        'rx_bytes': 'sum',
        'tx_bytes': 'sum',
        'duration_s': 'sum',
        'reset_event': 'sum',
        'anomaly': 'sum'
    }).reset_index()
    
    # Calculate derived metrics
    hourly['total_gb'] = (hourly['rx_bytes'] + hourly['tx_bytes']) / (1024**3)
    hourly['rx_gb'] = hourly['rx_bytes'] / (1024**3)
    hourly['tx_gb'] = hourly['tx_bytes'] / (1024**3)
    hourly['avg_rate_mbps'] = (hourly['total_gb'] * 1024 * 8) / (hourly['duration_s'] / 3600) if hourly['duration_s'].sum() > 0 else 0
    
    return hourly

def aggregate_daily_data(df: pd.DataFrame, timezone) -> pd.DataFrame:
    """
    Aggregate data into daily buckets with timezone support
    
    Args:
        df: DataFrame with bandwidth data
        timezone: Timezone for aggregation
    
    Returns:
        DataFrame with daily aggregates
    """
    print_status("Computing daily aggregates...", "PROCESS")
    
    df_local = df.copy()
    df_local['date'] = df_local['end'].apply(
        lambda x: convert_to_local_time(x, timezone).date()
    )
    
    # Group by date
    daily = df_local.groupby('date').agg({
        'rx_bytes': 'sum',
        'tx_bytes': 'sum',
        'duration_s': 'sum',
        'reset_event': 'sum',
        'anomaly': 'sum'
    }).reset_index()
    
    # Calculate derived metrics
    daily['total_gb'] = (daily['rx_bytes'] + daily['tx_bytes']) / (1024**3)
    daily['rx_gb'] = daily['rx_bytes'] / (1024**3)
    daily['tx_gb'] = daily['tx_bytes'] / (1024**3)
    daily['avg_rate_mbps'] = (daily['total_gb'] * 1024 * 8) / (daily['duration_s'] / 3600) if daily['duration_s'].sum() > 0 else 0
    
    return daily

def detect_peak_usage(hourly_df: pd.DataFrame, daily_df: pd.DataFrame, timezone) -> Dict:
    """
    Detect peak usage hours and days
    
    Args:
        hourly_df: Hourly aggregated data
        daily_df: Daily aggregated data
        timezone: Timezone for reporting
    
    Returns:
        Dictionary with peak analysis results
    """
    print_status("Analyzing peak usage patterns...", "PROCESS")
    
    results = {}
    
    # Peak hour detection
    if not hourly_df.empty:
        peak_hour_row = hourly_df.loc[hourly_df['total_gb'].idxmax()]
        results['peak_hour'] = {
            'time': peak_hour_row['hour_start'],
            'total_gb': peak_hour_row['total_gb'],
            'download_gb': peak_hour_row['rx_gb'],
            'upload_gb': peak_hour_row['tx_gb'],
            'rate_mbps': peak_hour_row['avg_rate_mbps']
        }
    
    # Peak day detection
    if not daily_df.empty:
        peak_day_row = daily_df.loc[daily_df['total_gb'].idxmax()]
        results['peak_day'] = {
            'date': peak_day_row['date'],
            'total_gb': peak_day_row['total_gb'],
            'download_gb': peak_day_row['rx_gb'],
            'upload_gb': peak_day_row['tx_gb'],
            'rate_mbps': peak_day_row['avg_rate_mbps'],
            'reset_events': int(peak_day_row['reset_event'])
        }
    
    # Low traffic window detection
    if not hourly_df.empty:
        # Filter out hours with very low data (might be incomplete)
        valid_hours = hourly_df[hourly_df['total_gb'] > 0.01]
        if not valid_hours.empty:
            low_traffic_hour = valid_hours.loc[valid_hours['total_gb'].idxmin()]
            results['low_traffic_hour'] = {
                'time': low_traffic_hour['hour_start'],
                'total_gb': low_traffic_hour['total_gb']
            }
    
    return results

def classify_usage(daily_df: pd.DataFrame) -> List[Dict]:
    """
    Classify days into usage categories
    
    Args:
        daily_df: Daily aggregated data
    
    Returns:
        List of classification results
    """
    classifications = []
    
    for _, day in daily_df.iterrows():
        total_gb = day['total_gb']
        
        if total_gb < USAGE_CLASSIFICATION["LIGHT"]["max_gb"]:
            category = "LIGHT"
        elif total_gb < USAGE_CLASSIFICATION["MODERATE"]["max_gb"]:
            category = "MODERATE"
        else:
            category = "HEAVY"
        
        classifications.append({
            'date': day['date'],
            'total_gb': total_gb,
            'category': category,
            'color': USAGE_CLASSIFICATION[category]["color"]
        })
    
    return classifications

def analyze_stability(daily_df: pd.DataFrame) -> Dict:
    """
    Analyze connection stability and reset patterns
    
    Args:
        daily_df: Daily aggregated data with reset events
    
    Returns:
        Stability analysis results
    """
    if daily_df.empty:
        return {}
    
    results = {
        'total_days': len(daily_df),
        'days_with_resets': len(daily_df[daily_df['reset_event'] > 0]),
        'total_resets': int(daily_df['reset_event'].sum()),
        'avg_resets_per_day': daily_df['reset_event'].mean(),
        'max_resets_in_day': int(daily_df['reset_event'].max()),
        'most_unstable_day': daily_df.loc[daily_df['reset_event'].idxmax()]['date'] if daily_df['reset_event'].max() > 0 else None
    }
    
    # Detect patterns (simple frequency analysis)
    if results['total_resets'] > 0:
        reset_days = daily_df[daily_df['reset_event'] > 0]
        if len(reset_days) > 1:
            # Simple pattern detection - check if resets occur at regular intervals
            reset_days_sorted = reset_days.sort_values('date')
            day_diffs = reset_days_sorted['date'].diff().dt.days.dropna()
            if len(day_diffs) > 0:
                results['avg_days_between_resets'] = day_diffs.mean()
                results['reset_regularity'] = "Regular" if day_diffs.std() < 1.0 else "Irregular"
    
    return results

# =============================================================================
# FORMATTING AND UTILITY FUNCTIONS
# =============================================================================
def format_size(mb: float) -> str:
    """
    Convert MB to human-readable format with appropriate units.
    
    Args:
        mb: Size in megabytes
        
    Returns:
        Formatted string with units
    """
    if mb >= 1024:
        return f"{mb/1024:.2f} GB"
    elif mb >= 1:
        return f"{mb:.2f} MB"
    else:
        return f"{mb*1024:.2f} KB"

def format_rate(kbps: float) -> str:
    """
    Format data rate in appropriate units.
    
    Args:
        kbps: Rate in kilobits per second
        
    Returns:
        Formatted rate string
    """
    if kbps >= 1000:
        return f"{kbps/1000:.1f} Mbps"
    else:
        return f"{kbps:.1f} Kbps"

def format_duration(seconds):
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{seconds // 60} minutes"
    elif seconds < 86400:
        return f"{seconds // 3600} hours"
    else:
        return f"{seconds // 86400} days"

# =============================================================================
# ENHANCED REPORTING FUNCTIONS
# =============================================================================
def print_peak_analysis(peak_data: Dict, timezone):
    """
    Print peak usage analysis results
    
    Args:
        peak_data: Peak analysis results
        timezone: Timezone for display
    """
    print_section("PEAK USAGE ANALYSIS")
    
    if 'peak_hour' in peak_data:
        peak = peak_data['peak_hour']
        local_time = peak['time'].strftime("%H:%M (%Z)")
        print(f"{Colors.GREEN}🏆 Peak Usage Hour:{Colors.RESET}")
        print(f"  {Colors.WHITE}• Time:{Colors.RESET} {Colors.YELLOW}{local_time}{Colors.RESET}")
        print(f"  {Colors.WHITE}• Total Data:{Colors.RESET} {Colors.RED}{peak['total_gb']:.2f} GB{Colors.RESET}")
        print(f"  {Colors.WHITE}• Download:{Colors.RESET} {peak['download_gb']:.2f} GB")
        print(f"  {Colors.WHITE}• Upload:{Colors.RESET} {peak['upload_gb']:.2f} GB")
        print(f"  {Colors.WHITE}• Average Rate:{Colors.RESET} {format_rate(peak['rate_mbps'] * 1000)}")
    
    if 'peak_day' in peak_data:
        peak = peak_data['peak_day']
        print(f"\n{Colors.GREEN}📅 Peak Usage Day:{Colors.RESET}")
        print(f"  {Colors.WHITE}• Date:{Colors.RESET} {Colors.YELLOW}{peak['date']}{Colors.RESET}")
        print(f"  {Colors.WHITE}• Total Data:{Colors.RESET} {Colors.RED}{peak['total_gb']:.2f} GB{Colors.RESET}")
        print(f"  {Colors.WHITE}• Reset Events:{Colors.RESET} {peak['reset_events']}")
    
    if 'low_traffic_hour' in peak_data:
        low = peak_data['low_traffic_hour']
        local_time = low['time'].strftime("%H:%M (%Z)")
        print(f"\n{Colors.GREEN}💤 Recommended Maintenance Window:{Colors.RESET}")
        print(f"  {Colors.WHITE}• Low Traffic Time:{Colors.RESET} {Colors.GREEN}{local_time}{Colors.RESET}")
        print(f"  {Colors.WHITE}• Expected Usage:{Colors.RESET} {low['total_gb']:.2f} GB")

def print_stability_report(stability_data: Dict, daily_classifications: List[Dict]):
    """
    Print connection stability report
    
    Args:
        stability_data: Stability analysis results
        daily_classifications: Daily usage classifications
    """
    print_section("CONNECTION STABILITY REPORT")
    
    if not stability_data:
        print_status("Insufficient data for stability analysis", "WARNING")
        return
    
    print(f"{Colors.GREEN}📊 Stability Overview:{Colors.RESET}")
    print(f"  {Colors.WHITE}• Monitoring Period:{Colors.RESET} {stability_data['total_days']} days")
    print(f"  {Colors.WHITE}• Days with Resets:{Colors.RESET} {stability_data['days_with_resets']}")
    print(f"  {Colors.WHITE}• Total Reset Events:{Colors.RESET} {Colors.RED if stability_data['total_resets'] > 0 else Colors.GREEN}{stability_data['total_resets']}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Average Resets/Day:{Colors.RESET} {stability_data['avg_resets_per_day']:.1f}")
    
    if stability_data['total_resets'] > 0:
        print(f"\n{Colors.GREEN}🔧 Reset Pattern Analysis:{Colors.RESET}")
        print(f"  {Colors.WHITE}• Most Unstable Day:{Colors.RESET} {stability_data['most_unstable_day']}")
        if 'avg_days_between_resets' in stability_data:
            print(f"  {Colors.WHITE}• Average Reset Interval:{Colors.RESET} {stability_data['avg_days_between_resets']:.1f} days")
            print(f"  {Colors.WHITE}• Pattern:{Colors.RESET} {stability_data['reset_regularity']}")
    
    # Usage classification summary
    if daily_classifications:
        print(f"\n{Colors.GREEN}📈 Usage Pattern Classification:{Colors.RESET}")
        category_counts = {}
        for classification in daily_classifications:
            cat = classification['category']
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        for category, count in category_counts.items():
            color = USAGE_CLASSIFICATION[category]["color"]
            percentage = (count / len(daily_classifications)) * 100
            print(f"  {color}• {category} Days:{Colors.RESET} {count} ({percentage:.1f}%)")

def print_comprehensive_stats(df: pd.DataFrame, events: Dict[str, int], interface: str, alert_gb: Optional[float] = None):
    """
    Print comprehensive statistics with professional formatting and reset analysis
    
    Args:
        df: DataFrame with analysis data
        events: Dictionary of counter events
        interface: Network interface name
        alert_gb: Alert threshold in GB
    """
    print_section("COMPREHENSIVE STATISTICS")
    
    # Basic statistics
    total_mb = df["total_mb"].sum()
    total_gb = total_mb / 1024
    total_duration = df["duration_s"].sum()
    
    # Reset-specific statistics
    reset_intervals = df[df["reset_event"] == True]
    normal_intervals = df[df["reset_event"] == False]
    
    print(f"{Colors.GREEN}📊 Data Overview:{Colors.RESET}")
    print(f"  {Colors.WHITE}• Interface:{Colors.RESET} {Colors.CYAN}{interface}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Snapshots Analyzed:{Colors.RESET} {Colors.YELLOW}{len(df) + 1:,}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Intervals Computed:{Colors.RESET} {Colors.YELLOW}{len(df):,}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Monitoring Duration:{Colors.RESET} {Colors.MAGENTA}{format_duration(total_duration)}{Colors.RESET}")
    
    # Enhanced counter events with reset analysis
    print(f"\n{Colors.GREEN}🔧 Counter Events Analysis:{Colors.RESET}")
    print(f"  {Colors.WHITE}• Counter Wraps:{Colors.RESET} {Colors.YELLOW}{events['wrap_events']:,}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Counter Resets:{Colors.RESET} {Colors.RED}{events['reset_events']:,}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Data Anomalies:{Colors.RESET} {Colors.MAGENTA}{events['anomalies']:,}{Colors.RESET}")
    
    if events['reset_events'] > 0:
        reset_percentage = (len(reset_intervals) / len(df)) * 100
        print(f"  {Colors.RED}• Reset Intervals:{Colors.RESET} {len(reset_intervals)} ({reset_percentage:.1f}% of total){Colors.RESET}")
        print(f"  {Colors.RED}• Estimated Router Reboots:{Colors.RESET} {events['reset_events']}{Colors.RESET}")
    
    # Data usage statistics
    print(f"\n{Colors.GREEN}📈 Data Usage Statistics:{Colors.RESET}")
    print(f"  {Colors.WHITE}• Total Transferred:{Colors.RESET} {Colors.CYAN}{format_size(total_mb)}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Download:{Colors.RESET} {Colors.GREEN}{format_size(df['rx_mb'].sum())}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Upload:{Colors.RESET} {Colors.RED}{format_size(df['tx_mb'].sum())}{Colors.RESET}")
    
    # Enhanced rate statistics
    if not normal_intervals.empty:
        avg_rate = normal_intervals["rate_kbps"].mean()
        max_rate = normal_intervals["rate_kbps"].max()
    else:
        avg_rate = df["rate_kbps"].mean()
        max_rate = df["rate_kbps"].max()
        
    print(f"  {Colors.WHITE}• Average Rate:{Colors.RESET} {Colors.MAGENTA}{format_rate(avg_rate)}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Peak Rate:{Colors.RESET} {Colors.YELLOW}{format_rate(max_rate)}{Colors.RESET}")
    
    # Data quality assessment
    print(f"\n{Colors.GREEN}🔍 Data Quality Assessment:{Colors.RESET}")
    quality_score = (len(normal_intervals) / len(df)) * 100 if len(df) > 0 else 0
    if quality_score >= 90:
        quality_color = Colors.GREEN
        quality_text = "Excellent"
    elif quality_score >= 75:
        quality_color = Colors.YELLOW
        quality_text = "Good"
    else:
        quality_color = Colors.RED
        quality_text = "Poor"
    
    print(f"  {Colors.WHITE}• Data Quality:{Colors.RESET} {quality_color}{quality_text} ({quality_score:.1f}%){Colors.RESET}")
    print(f"  {Colors.WHITE}• Reliable Intervals:{Colors.RESET} {len(normal_intervals)}/{len(df)}")
    
    # Alert system with progress bar
    if alert_gb and total_gb > alert_gb:
        print(f"\n{Colors.RED}{Colors.BOLD}🚨 SECURITY ALERT: Data usage ({total_gb:.2f} GB) "
              f"exceeds threshold ({alert_gb} GB)!{Colors.RESET}")
    elif alert_gb:
        print_usage_progress_bar(total_gb, alert_gb)

def print_detailed_intervals(df: pd.DataFrame):
    """
    Print detailed interval breakdown with reset events highlighted
    
    Args:
        df: DataFrame with interval data
    """
    print_section("DETAILED INTERVAL ANALYSIS")
    
    print(f"{Colors.BOLD}{'Start Time':<20} {'End Time':<20} {'Duration':<8} "
          f"{'Download':<12} {'Upload':<10} {'Total':<12} {'Rate':<15} {'Reset':<6}{Colors.RESET}")
    print(f"{Colors.GRAY}{'─' * 105}{Colors.RESET}")
    
    for _, row in df.iterrows():
        start_str = row["start"].strftime("%m/%d %H:%M:%S")
        end_str = row["end"].strftime("%m/%d %H:%M:%S")
        
        # Color coding for reset events
        reset_indicator = "🔴" if row["reset_event"] else "  "
        anomaly_indicator = "⚠️" if row["anomaly"] else "  "
        
        print(f"{start_str:<20} {end_str:<20} {int(row['duration_s']):<8} "
              f"{format_size(row['rx_mb']):<12} {format_size(row['tx_mb']):<10} "
              f"{format_size(row['total_mb']):<12} {format_rate(row['rate_kbps']):<15} "
              f"{reset_indicator}{anomaly_indicator}")

# =============================================================================
# VISUALIZATION FUNCTIONS
# =============================================================================
def generate_chart(df: pd.DataFrame, interface: str, out_path: str):
    """
    Generate professional bandwidth usage chart with reset events highlighted.
    
    Args:
        df: DataFrame with bandwidth data
        interface: Network interface name
        out_path: Output path for the chart
    """
    print_status(f"Generating professional chart: {os.path.basename(out_path)}", "PROCESS")
    
    try:
        plt.style.use("seaborn-v0_8")
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        
        # Set professional styling
        fig.patch.set_facecolor("#f8f9fa")
        ax1.set_facecolor("#ffffff")
        ax2.set_facecolor("#ffffff")
        
        # Plot 1: Data volume over time
        ax1.plot(df["end"], df["total_mb"], label="Total", 
                color="#2c3e50", linewidth=2.5, marker='o', markersize=3)
        ax1.plot(df["end"], df["rx_mb"], label="Download", 
                color="#27ae60", linestyle="--", linewidth=2)
        ax1.plot(df["end"], df["tx_mb"], label="Upload", 
                color="#e74c3c", linestyle=":", linewidth=2)

        # Highlight reset events
        reset_points = df[df["reset_event"] == True]
        if not reset_points.empty:
            ax1.scatter(reset_points["end"], reset_points["total_mb"], 
                       color='red', s=100, zorder=5, label='Reset Events',
                       marker='X', edgecolors='black', linewidth=2)

        # Plot 2: Data rate over time
        ax2.plot(df["end"], df["rate_kbps"] / 1000, label="Transfer Rate", 
                color="#8e44ad", linewidth=2.5)

        # Professional chart styling for first subplot
        ax1.set_title(f"Bandwidth Usage Analysis - {interface}", 
                     fontsize=14, fontweight='bold', pad=20, color='#2c3e50')
        ax1.set_ylabel("Data Transferred (MB)", fontsize=11, fontweight='bold')
        ax1.legend(loc='upper left', frameon=True, fancybox=True, 
                  shadow=True, framealpha=0.9)
        ax1.grid(True, linestyle='--', alpha=0.7, color='#bdc3c7')

        # Professional chart styling for second subplot
        ax2.set_title("Data Transfer Rate", fontsize=12, fontweight='bold', pad=15)
        ax2.set_xlabel("Time", fontsize=11, fontweight='bold')
        ax2.set_ylabel("Transfer Rate (Mbps)", fontsize=11, fontweight='bold')
        ax2.legend(loc='upper left')
        ax2.grid(True, linestyle='--', alpha=0.7, color='#bdc3c7')

        # Format x-axis for better readability
        for ax in [ax1, ax2]:
            plt.sca(ax)
            plt.xticks(rotation=45)
        
        plt.tight_layout()
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        plt.savefig(out_path, facecolor=fig.get_facecolor(), dpi=150, 
                   bbox_inches='tight')
        plt.close()
        
        print_status(f"Professional chart generated: {out_path}", "SUCCESS")
        
    except Exception as e:
        print_status(f"Chart generation failed: {str(e)}", "ERROR")

def generate_hourly_chart(hourly_df: pd.DataFrame, interface: str, timezone):
    """
    Generate hourly usage chart
    
    Args:
        hourly_df: Hourly aggregated data
        interface: Network interface name
        timezone: Timezone for display
    """
    if hourly_df.empty:
        return
        
    try:
        chart_path = os.path.join(CHART_DIR, f"hourly_usage_{interface}.png")
        print_status(f"Generating hourly usage chart: {os.path.basename(chart_path)}", "PROCESS")
        
        plt.style.use("seaborn-v0_8")
        fig, ax = plt.subplots(figsize=(12, 6))
        
        # Convert to local time for x-axis
        local_times = [convert_to_local_time(ts, timezone) for ts in hourly_df['hour_start']]
        
        # Plot hourly usage
        bars = ax.bar(local_times, hourly_df['total_gb'], 
                     color='#3498db', alpha=0.7, label='Hourly Usage')
        
        # Highlight peak hour
        peak_idx = hourly_df['total_gb'].idxmax()
        bars[peak_idx].set_color('#e74c3c')
        bars[peak_idx].set_alpha(1.0)
        
        ax.set_title(f"Hourly Bandwidth Usage - {interface}", 
                    fontsize=14, fontweight='bold', pad=20)
        ax.set_xlabel("Time", fontsize=11, fontweight='bold')
        ax.set_ylabel("Data Transferred (GB)", fontsize=11, fontweight='bold')
        ax.grid(True, linestyle='--', alpha=0.7, axis='y')
        
        # Format x-axis
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        os.makedirs(os.path.dirname(chart_path), exist_ok=True)
        plt.savefig(chart_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        print_status(f"Hourly usage chart generated: {chart_path}", "SUCCESS")
        
    except Exception as e:
        print_status(f"Hourly chart generation failed: {str(e)}", "ERROR")

# =============================================================================
# EXPORT FUNCTIONS
# =============================================================================
def export_csv(df: pd.DataFrame, interface: str, export_path: Optional[str] = None):
    """
    Export analysis results to CSV file with enhanced reset information.
    
    Args:
        df: DataFrame with analysis data
        interface: Network interface name
        export_path: Custom export path (optional)
    """
    print_status("Exporting analysis data to CSV...", "PROCESS")
    
    try:
        if export_path is None:
            export_path = os.path.join(EXPORT_DIR, f"{interface}_usage.csv")
        elif os.path.isdir(export_path):
            export_path = os.path.join(export_path, f"{interface}_usage.csv")
        
        os.makedirs(os.path.dirname(export_path), exist_ok=True)
        
        # Create enhanced CSV with reset information
        export_df = df.copy()
        export_df["start_time"] = export_df["start"].dt.strftime("%Y-%m-%d %H:%M:%S")
        export_df["end_time"] = export_df["end"].dt.strftime("%Y-%m-%d %H:%M:%S")
        export_df["download_mb"] = export_df["rx_mb"].round(2)
        export_df["upload_mb"] = export_df["tx_mb"].round(2)
        export_df["total_mb"] = export_df["total_mb"].round(2)
        export_df["rate_mbps"] = (export_df["rate_kbps"] / 1000).round(2)
        export_df["reset_event"] = export_df["reset_event"].astype(bool)
        export_df["anomaly"] = export_df["anomaly"].astype(bool)
        
        columns_to_export = [
            "start_time", "end_time", "duration_s", "download_mb", 
            "upload_mb", "total_mb", "rate_mbps", "reset_event", "anomaly"
        ]
        
        export_df[columns_to_export].to_csv(export_path, index=False)
        print_status(f"Enhanced data exported to CSV: {export_path}", "SUCCESS")
        
    except Exception as e:
        print_status(f"CSV export failed: {str(e)}", "ERROR")

def export_aggregated_data(hourly_df: pd.DataFrame, daily_df: pd.DataFrame, export_dir: str):
    """
    Export hourly and daily aggregated data to CSV
    
    Args:
        hourly_df: Hourly aggregated data
        daily_df: Daily aggregated data  
        export_dir: Export directory
    """
    os.makedirs(export_dir, exist_ok=True)
    
    if not hourly_df.empty:
        hourly_export = hourly_df.copy()
        hourly_export['hour_start'] = hourly_export['hour_start'].dt.strftime("%Y-%m-%d %H:%M:%S %Z")
        export_columns = ['hour_start', 'rx_gb', 'tx_gb', 'total_gb', 'avg_rate_mbps', 'reset_event', 'anomaly']
        hourly_export[export_columns].to_csv(
            os.path.join(export_dir, "gb_per_hour.csv"), index=False
        )
        print_status(f"Hourly data exported: {os.path.join(export_dir, 'gb_per_hour.csv')}", "SUCCESS")
    
    if not daily_df.empty:
        daily_export = daily_df.copy()
        export_columns = ['date', 'rx_gb', 'tx_gb', 'total_gb', 'avg_rate_mbps', 'reset_event', 'anomaly']
        daily_export[export_columns].to_csv(
            os.path.join(export_dir, "gb_per_day.csv"), index=False
        )
        print_status(f"Daily data exported: {os.path.join(export_dir, 'gb_per_day.csv')}", "SUCCESS")

# =============================================================================
# MAIN APPLICATION
# =============================================================================
def main():
    """Enhanced main execution function"""
    # Display professional banner
    print_banner()
    print_section("INITIALIZATION")
    
    # Setup argument parser and load cache
    parser = setup_arg_parser()
    cached_args = load_cached_args()
    
    # Merge cached args with CLI args - now returns both the args and new cache
    args, new_cache = merge_args_with_cache(parser, cached_args)
    
    # Setup timezone
    timezone = setup_timezone(args.timezone)
    
    # Display configuration
    print_status(f"Working directory: {os.path.abspath(args.log_dir)}", "INFO")
    print_status(f"Network interface: {args.interface}", "INFO")
    print_status(f"Timezone: {args.timezone}", "INFO")
    print_status(f"Reset threshold: {args.reset_threshold*100}%", "INFO")
    print_status(f"Chart generation: {'Enabled' if args.chart else 'Disabled'}", "INFO")
    print_status(f"Detailed output: {'Enabled' if args.details else 'Disabled'}", "INFO")
    print_status(f"Export: {'Enabled' if args.export else 'Disabled'}", "INFO")
    print_status(f"Aggregation: {args.aggregate if args.aggregate else 'Disabled'}", "INFO")
    print_status(f"Peak analysis: {'Enabled' if args.peak_analysis else 'Disabled'}", "INFO")
    print_status(f"Stability report: {'Enabled' if args.stability_report else 'Disabled'}", "INFO")
    if args.alert_gb:
        print_status(f"Alert threshold: {args.alert_gb} GB", "INFO")
    
    # Validate directory
    if not os.path.exists(args.log_dir):
        print_status(f"Directory '{args.log_dir}' not found!", "ERROR")
        sys.exit(1)
    
    try:
        # Analyze bandwidth data with enhanced reset detection
        print_section("DATA ANALYSIS")
        df, events = analyze_bandwidth(args.log_dir, args.interface, args.reset_threshold)
        if df is None:
            sys.exit(1)
        
        # Enhanced aggregation and analysis
        hourly_df, daily_df = pd.DataFrame(), pd.DataFrame()
        peak_data, stability_data, classifications = {}, {}, []
        
        if args.aggregate or args.peak_analysis or args.stability_report:
            # Compute aggregations
            if args.aggregate in ['hourly', 'both'] or args.peak_analysis:
                hourly_df = aggregate_hourly_data(df, timezone)
            if args.aggregate in ['daily', 'both'] or args.peak_analysis or args.stability_report:
                daily_df = aggregate_daily_data(df, timezone)
            
            if args.peak_analysis:
                peak_data = detect_peak_usage(hourly_df, daily_df, timezone)
                classifications = classify_usage(daily_df)
            
            if args.stability_report:
                stability_data = analyze_stability(daily_df)
        
        # Display comprehensive statistics
        print_comprehensive_stats(df, events, args.interface, args.alert_gb)
        
        # Enhanced reporting
        if args.peak_analysis and peak_data:
            print_peak_analysis(peak_data, timezone)
        
        if args.stability_report and stability_data:
            print_stability_report(stability_data, classifications)
        
        # Detailed interval breakdown
        if args.details:
            print_detailed_intervals(df)
        
        # Generate outputs
        print_section("OUTPUT GENERATION")
        
        if args.chart:
            chart_path = os.path.join(CHART_DIR, f"bandwidth_usage_{args.interface}.png")
            generate_chart(df, args.interface, chart_path)
            
            # Generate hourly chart if data exists
            if not hourly_df.empty and (args.aggregate or args.peak_analysis):
                generate_hourly_chart(hourly_df, args.interface, timezone)
        
        if args.export:
            export_path = args.export if isinstance(args.export, str) else None
            export_csv(df, args.interface, export_path)
            
            # Export aggregated data
            if args.aggregate:
                export_dir = EXPORT_DIR if export_path is None else export_path
                if isinstance(export_dir, str) and not os.path.isdir(export_dir):
                    export_dir = os.path.dirname(export_dir)
                export_aggregated_data(hourly_df, daily_df, export_dir)
        
        # Save CURRENT arguments to cache for next run (not merged ones)
        save_args_to_cache(new_cache)
        
        # Success message with data quality summary
        print_section("ANALYSIS COMPLETE")
        normal_intervals = len(df[df["reset_event"] == False])
        total_intervals = len(df)
        quality_percentage = (normal_intervals / total_intervals) * 100
        
        print_status(f"Bandwidth analysis completed successfully! 🎉", "SUCCESS")
        print_status(f"Data Quality: {quality_percentage:.1f}% reliable intervals ({normal_intervals}/{total_intervals})", "INFO")
        if events['reset_events'] > 0:
            print_status(f"Detected {events['reset_events']} counter reset events (router reboots)", "RESET")
        
        # Summary of new features used
        if args.peak_analysis and peak_data:
            peak_gb = peak_data.get('peak_hour', {}).get('total_gb', 0)
            print_status(f"Peak Usage: {peak_gb:.2f} GB/hour detected", "INFO")
        
    except KeyboardInterrupt:
        print_status("\nProcess interrupted by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        print_status(f"Unexpected error: {str(e)}", "ERROR")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
