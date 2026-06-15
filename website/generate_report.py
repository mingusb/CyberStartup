import os
import sys
import json
from fpdf import FPDF
from fpdf.enums import XPos, YPos

def generate_pdf_report(output_path: str = None, data: dict = None) -> str:
    """
    Natively generates the Cyber Startup PDF ROI Report in-process.
    """
    # Default output path relative to project root
    if output_path is None:
        output_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs/whitepaper/roi_report.pdf")
    
    abs_output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_output_path), exist_ok=True)
    
    # Load dashboard telemetry
    if data is None:
        dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.json")
        try:
            with open(dashboard_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            data = {
                "mode": "N/A",
                "threats_preempted": "N/A",
                "nodes_saved": "N/A",
                "cost_avoided": "N/A",
                "hours_saved": "N/A",
                "blast_radius_score": 0.5
            }
    
    # Generate PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=16)
    pdf.cell(200, 10, text="Cyber Startup Pitch Deck ROI Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    
    pdf.set_font("helvetica", size=12)
    pdf.cell(200, 10, text=f"System Mode: {data.get('mode', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    pdf.cell(200, 10, text=f"Threats Preempted: {data.get('threats_preempted', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    pdf.cell(200, 10, text=f"Nodes Saved: {data.get('nodes_saved', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    pdf.cell(200, 10, text=f"Cost Avoided: {data.get('cost_avoided', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    pdf.cell(200, 10, text=f"Operational Hours Saved: {data.get('hours_saved', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    
    score = data.get('blast_radius_score', 0.5)
    brs_val = int(score * 100) if isinstance(score, (int, float)) else 50
    pdf.cell(200, 10, text=f"Blast Radius Score: {brs_val}/100", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    
    pdf.output(abs_output_path)
    print(f"Report successfully generated at: {abs_output_path}")
    return abs_output_path

def generate_report(output_path: str = None, data: dict = None) -> str:
    """
    Compatibility wrapper calling generate_pdf_report.
    """
    return generate_pdf_report(output_path=output_path, data=data)

def main():
    cli_path = sys.argv[1] if len(sys.argv) > 1 else None
    resolved_path = generate_pdf_report(output_path=cli_path)
    print(f"Report successfully generated at: {resolved_path}")

if __name__ == "__main__":
    main()

