#!/usr/bin/env python3
"""
ATS-Friendly Resume PDF Generator
Converts text resume to ATS-compliant PDF format
"""

import sys
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import black, blue
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfgen import canvas

def create_ats_styles():
    """Create ATS-friendly styles"""
    styles = getSampleStyleSheet()

    # Custom styles for ATS compatibility
    styles.add(ParagraphStyle(
        name='ATSTitle',
        parent=styles['Title'],
        fontSize=16,
        spaceAfter=6,
        alignment=TA_CENTER,
        textColor=black,
        fontName='Helvetica-Bold'
    ))

    styles.add(ParagraphStyle(
        name='ATSSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=6,
        alignment=TA_CENTER,
        textColor=blue,
        fontName='Helvetica-Bold'
    ))

    styles.add(ParagraphStyle(
        name='ATSContact',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=12,
        alignment=TA_CENTER,
        textColor=black,
        fontName='Helvetica'
    ))

    styles.add(ParagraphStyle(
        name='ATSHeading',
        parent=styles['Heading2'],
        fontSize=12,
        spaceAfter=6,
        spaceBefore=12,
        textColor=black,
        fontName='Helvetica-Bold',
        borderWidth=0,
        borderColor=black,
        borderPadding=0
    ))

    styles.add(ParagraphStyle(
        name='ATSSubheading',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=3,
        textColor=black,
        fontName='Helvetica-Bold'
    ))

    styles.add(ParagraphStyle(
        name='ATSBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6,
        textColor=black,
        fontName='Helvetica',
        alignment=TA_JUSTIFY
    ))

    styles.add(ParagraphStyle(
        name='ATSBullet',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=3,
        leftIndent=12,
        textColor=black,
        fontName='Helvetica'
    ))

    return styles

def parse_resume_text(file_path):
    """Parse the resume text file into structured sections"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    lines = [line.strip() for line in content.split('\n') if line.strip()]

    resume_data = {
        'header': {},
        'sections': {}
    }

    # Parse header
    resume_data['header']['name'] = lines[0]
    resume_data['header']['contact'] = lines[1]

    # Parse sections
    current_section = None
    current_subsection = None

    for line in lines[2:]:
        # Check if it's a main section
        if line.isupper() and not line.startswith('•') and not line.startswith('-'):
            current_section = line
            resume_data['sections'][current_section] = []
            current_subsection = None
        elif current_section:
            # Check if it's a job/experience entry
            if any(keyword in line for keyword in ['—', 'LTD', 'Technologies', 'College', 'Certificate']):
                current_subsection = {
                    'title': line,
                    'details': []
                }
                resume_data['sections'][current_section].append(current_subsection)
            elif current_subsection and (line.startswith('•') or line.startswith('-')):
                # Bullet point
                current_subsection['details'].append(line)
            elif current_subsection:
                # Additional details
                current_subsection['details'].append(line)
            else:
                # General section content
                resume_data['sections'][current_section].append({'content': line})

    return resume_data

def create_ats_pdf(resume_data, output_path):
    """Create ATS-compliant PDF"""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch,
        leftMargin=0.75*inch,
        rightMargin=0.75*inch
    )

    styles = create_ats_styles()
    story = []

    # Header
    story.append(Paragraph(resume_data['header']['name'], styles['ATSTitle']))
    story.append(Paragraph("Cloud Security | DevSecOps Engineer", styles['ATSSubtitle']))
    story.append(Paragraph(resume_data['header']['contact'], styles['ATSContact']))

    # Sections
    for section_name, section_content in resume_data['sections'].items():
        # Section heading
        story.append(Paragraph(section_name, styles['ATSHeading']))

        if section_name == "PROFESSIONAL SUMMARY":
            # Handle summary as continuous text
            for item in section_content:
                if 'content' in item:
                    story.append(Paragraph(item['content'], styles['ATSBody']))

        elif section_name == "PROFESSIONAL SKILLS":
            # Handle skills in a structured format
            for item in section_content:
                if 'content' in item:
                    story.append(Paragraph(item['content'], styles['ATSBody']))

        elif section_name == "PROFESSIONAL EXPERIENCE":
            # Handle experience entries
            for item in section_content:
                if 'title' in item:
                    # Split job title and company/dates
                    title_parts = item['title'].split(' — ')
                    if len(title_parts) >= 2:
                        company_info = title_parts[0]
                        position_info = title_parts[1] if len(title_parts) > 1 else ""

                        story.append(Paragraph(company_info, styles['ATSSubheading']))
                        if position_info:
                            story.append(Paragraph(position_info, styles['ATSBody']))
                    else:
                        story.append(Paragraph(item['title'], styles['ATSSubheading']))

                    # Add job details
                    for detail in item['details']:
                        if detail.startswith('•'):
                            clean_detail = detail[1:].strip()
                            story.append(Paragraph(f"• {clean_detail}", styles['ATSBullet']))
                        elif detail.strip():
                            story.append(Paragraph(detail, styles['ATSBody']))

                    story.append(Spacer(1, 6))

        elif section_name == "CERTIFICATIONS":
            # Handle certifications
            for item in section_content:
                if 'content' in item:
                    story.append(Paragraph(f"• {item['content']}", styles['ATSBullet']))

        elif section_name == "EDUCATION":
            # Handle education
            for item in section_content:
                if 'content' in item:
                    story.append(Paragraph(item['content'], styles['ATSBody']))

        elif section_name == "NOTABLE PROJECTS":
            # Handle projects
            for item in section_content:
                if 'title' in item:
                    story.append(Paragraph(item['title'], styles['ATSSubheading']))
                    for detail in item['details']:
                        if detail.startswith('•'):
                            clean_detail = detail[1:].strip()
                            story.append(Paragraph(f"• {clean_detail}", styles['ATSBullet']))
                        elif detail.strip():
                            story.append(Paragraph(detail, styles['ATSBody']))
                    story.append(Spacer(1, 6))

        story.append(Spacer(1, 12))

    # Build PDF
    doc.build(story)
    print(f"ATS-friendly PDF created: {output_path}")

def main():
    input_file = "/Users/ade/Desktop/RESUMEs/DEVSECOPS/BASE13_IMPROVED.txt"
    output_file = "/Users/ade/Desktop/RESUMEs/DEVSECOPS/Adeyinka_Fajobi_DevSecOps_Resume_ATS.pdf"

    if not os.path.exists(input_file):
        print(f"Error: Input file not found: {input_file}")
        return 1

    try:
        # Install reportlab if not available
        try:
            import reportlab
        except ImportError:
            print("Installing reportlab for PDF generation...")
            os.system("pip3 install reportlab")
            import reportlab

        resume_data = parse_resume_text(input_file)
        create_ats_pdf(resume_data, output_file)

        print(f"✅ ATS-compliant resume PDF created successfully!")
        print(f"📄 File saved to: {output_file}")
        print(f"📁 File size: {os.path.getsize(output_file)} bytes")

        return 0

    except Exception as e:
        print(f"Error creating PDF: {str(e)}")
        return 1

if __name__ == '__main__':
    exit(main())