#!/usr/bin/env python3
import os
import sys
import subprocess
import re
import zlib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

def extract_text_from_pdf(pdf_path):
    with open(pdf_path, 'rb') as f:
        content = f.read()
    
    # PDF Magic byte check
    if not content.startswith(b'%PDF-'):
        raise ValueError(f"Invalid PDF magic header in {pdf_path}")
    
    streams = re.findall(b'stream\r?\n(.*?)\r?\nendstream', content, re.DOTALL)
    decompressed_texts = []
    for s in streams:
        try:
            decompressed = zlib.decompress(s)
            decompressed_texts.append(decompressed.decode('utf-8', errors='ignore'))
        except Exception:
            try:
                # Try raw decompression without header
                decompressed = zlib.decompress(s, -15)
                decompressed_texts.append(decompressed.decode('utf-8', errors='ignore'))
            except Exception:
                pass
    return "\n".join(decompressed_texts)

def test_combination(env_vars):
    pdf_path = os.path.join(PROJECT_ROOT, "docs/whitepaper/pitch_deck.pdf")
    if os.path.exists(pdf_path):
        os.remove(pdf_path)
        
    env = os.environ.copy()
    env.update(env_vars)
    
    # We must ensure CYBERSTARTUP_NO_SUDO, CYBERSTARTUP_BUILD_STEP, CYBERSTARTUP_MOCK_TELEMETRY are set/unset exactly as requested
    for var in ["CYBERSTARTUP_NO_SUDO", "CYBERSTARTUP_BUILD_STEP", "CYBERSTARTUP_MOCK_TELEMETRY"]:
        if var not in env_vars:
            env.pop(var, None)
            
    print(f"\n[Test] Running gen_pitch_deck.py with env: {env_vars}")
    script_path = os.path.join(PROJECT_ROOT, "scripts/gen_pitch_deck.py")
    
    # Run the generator script
    res = subprocess.run([sys.executable, script_path], env=env, capture_output=True, text=True, timeout=15)
    
    # Assert execution success
    if res.returncode != 0:
        print(f"Error: gen_pitch_deck.py failed with exit code {res.returncode}")
        print(f"Stdout:\n{res.stdout}")
        print(f"Stderr:\n{res.stderr}")
        return False
        
    # Assert bypassed live API fetch message is present in the output
    if "Bypassing live API fetch in decoupled mode" not in res.stdout:
        print("Error: Expected urllib bypass message not found in stdout")
        print(f"Stdout:\n{res.stdout}")
        return False
        
    # Assert PDF file was created and has non-zero size
    if not os.path.exists(pdf_path):
        print(f"Error: {pdf_path} was not created.")
        return False
        
    size = os.path.getsize(pdf_path)
    print(f"Success: {pdf_path} created, size: {size} bytes")
    if size == 0:
        print("Error: Pitch deck PDF size is zero.")
        return False
        
    # Extract text and verify mock CLI logs are present
    try:
        pdf_text = extract_text_from_pdf(pdf_path)
    except Exception as e:
        print(f"Error: PDF validation failed: {e}")
        return False
        
    required_strings = [
        "CYBERSTARTUP: Hardware-Enforced Architecture",
        "ENTERPRISE MODE ACTIVATED: Hardware-Enforced TEE Engine Online",
        "Generated Permutation-Invariant Threat Conditioning Vector",
        "Z3 Deterministic Validation: AST proved satisfiable.",
        "CYBERSTARTUP Execution Terminated Successfully."
    ]
    
    for s in required_strings:
        if s not in pdf_text:
            print(f"Error: Expected log substring not found in PDF: '{s}'")
            return False
            
    print("Success: Pitch deck PDF contains all required mock CLI logs.")
    return True

def main():
    print("==========================================================")
    print("Starting Pitch Deck PDF Generation & Robustness Verification")
    print("==========================================================")
    
    # 7 Combinations of environment variables (at least one is set)
    combinations = [
        {"CYBERSTARTUP_NO_SUDO": "1"},
        {"CYBERSTARTUP_BUILD_STEP": "1"},
        {"CYBERSTARTUP_MOCK_TELEMETRY": "1"},
        {"CYBERSTARTUP_NO_SUDO": "1", "CYBERSTARTUP_BUILD_STEP": "1"},
        {"CYBERSTARTUP_NO_SUDO": "1", "CYBERSTARTUP_MOCK_TELEMETRY": "1"},
        {"CYBERSTARTUP_BUILD_STEP": "1", "CYBERSTARTUP_MOCK_TELEMETRY": "1"},
        {"CYBERSTARTUP_NO_SUDO": "1", "CYBERSTARTUP_BUILD_STEP": "1", "CYBERSTARTUP_MOCK_TELEMETRY": "1"}
    ]
    
    failed_combinations = []
    for comb in combinations:
        success = test_combination(comb)
        if not success:
            failed_combinations.append(comb)
            
    # Check other PDF files
    print("\n==========================================================")
    print("Verifying Other Document Compilations")
    print("==========================================================")
    
    # 1. Patent Draft PDF
    patent_dir = os.path.join(PROJECT_ROOT, "docs/patent")
    patent_pdf = os.path.join(patent_dir, "patent_draft.pdf")
    if os.path.exists(patent_pdf):
        os.remove(patent_pdf)
    print("Compiling patent draft PDF...")
    res_patent = subprocess.run(["make", "-C", patent_dir], capture_output=True, text=True)
    if res_patent.returncode != 0 or not os.path.exists(patent_pdf) or os.path.getsize(patent_pdf) == 0:
        print("Error: Patent draft compilation failed.")
        print(res_patent.stderr)
        failed_combinations.append({"Patent Compilation": "Failed"})
    else:
        print(f"Success: patent_draft.pdf compiled, size: {os.path.getsize(patent_pdf)} bytes")
        try:
            extract_text_from_pdf(patent_pdf)
            print("Success: patent_draft.pdf is valid.")
        except Exception as e:
            print(f"Error: patent_draft.pdf invalid: {e}")
            failed_combinations.append({"Patent Validity": "Failed"})
            
    # 2. Whitepaper PDF
    whitepaper_dir = os.path.join(PROJECT_ROOT, "docs/whitepaper")
    whitepaper_pdf = os.path.join(whitepaper_dir, "cyberstartup_whitepaper.pdf")
    if os.path.exists(whitepaper_pdf):
        os.remove(whitepaper_pdf)
    print("\nCompiling whitepaper PDF via Pandoc...")
    res_whitepaper = subprocess.run([
        "pandoc", 
        os.path.join(whitepaper_dir, "cyberstartup_whitepaper.md"), 
        "-o", 
        whitepaper_pdf, 
        "-V", 
        "geometry:margin=1in"
    ], capture_output=True, text=True)
    if res_whitepaper.returncode != 0 or not os.path.exists(whitepaper_pdf) or os.path.getsize(whitepaper_pdf) == 0:
        print("Error: Whitepaper PDF compilation failed.")
        print(res_whitepaper.stderr)
        failed_combinations.append({"Whitepaper Compilation": "Failed"})
    else:
        print(f"Success: cyberstartup_whitepaper.pdf compiled, size: {os.path.getsize(whitepaper_pdf)} bytes")
        try:
            extract_text_from_pdf(whitepaper_pdf)
            print("Success: cyberstartup_whitepaper.pdf is valid.")
        except Exception as e:
            print(f"Error: cyberstartup_whitepaper.pdf invalid: {e}")
            failed_combinations.append({"Whitepaper Validity": "Failed"})
            
    # 3. ROI Report PDF
    roi_pdf = os.path.join(whitepaper_dir, "roi_report.pdf")
    if os.path.exists(roi_pdf):
        os.remove(roi_pdf)
    print("\nGenerating ROI report PDF...")
    roi_script = os.path.join(PROJECT_ROOT, "website/generate_report.py")
    res_roi = subprocess.run([sys.executable, roi_script], capture_output=True, text=True)
    if res_roi.returncode != 0 or not os.path.exists(roi_pdf) or os.path.getsize(roi_pdf) == 0:
        print("Error: ROI report PDF generation failed.")
        print(res_roi.stderr)
        failed_combinations.append({"ROI Report Generation": "Failed"})
    else:
        print(f"Success: roi_report.pdf generated, size: {os.path.getsize(roi_pdf)} bytes")
        try:
            extract_text_from_pdf(roi_pdf)
            print("Success: roi_report.pdf is valid.")
        except Exception as e:
            print(f"Error: roi_report.pdf invalid: {e}")
            failed_combinations.append({"ROI Report Validity": "Failed"})
            
    # Summary of verification
    print("\n==========================================================")
    print("VERIFICATION SUMMARY")
    print("==========================================================")
    if not failed_combinations:
        print("ALL TESTS PASSED SUCCESSFULLY!")
        print("All environment variable combinations bypassed sudo/urllib correctly.")
        print("Generated PDFs are non-zero size, valid, and contain required information.")
        sys.exit(0)
    else:
        print(f"FAILURE: {len(failed_combinations)} test scenarios failed.")
        for f in failed_combinations:
            print(f" - {f}")
        sys.exit(1)

if __name__ == "__main__":
    main()
