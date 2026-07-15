from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import json
import csv
import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from app.database import get_db
from app.schemas import ReportCreate, Report
from app.models import (
    Report as ReportModel, 
    AIUsageLog as AIUsageLogModel, 
    PolicyViolation as PolicyViolationModel,
    AuditExport as AuditExportModel
)
from app.models import User as UserModel, UserRole
from app.security import get_current_user

router = APIRouter()


@router.post("/", response_model=Report, status_code=status.HTTP_201_CREATED)
def create_report(
    report: ReportCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    if current_user.role != UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Admin access required")
    db_report = ReportModel(
        title=report.title,
        description=report.description,
        report_type=report.report_type,
        data=report.data
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report


@router.get("/", response_model=List[Report])
def get_reports(
    skip: int = 0, 
    limit: int = 100, 
    report_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    if current_user.role not in {UserRole.ADMIN.value, UserRole.AUDITOR.value}:
        raise HTTPException(status_code=403, detail="Admin or auditor access required")
    query = db.query(ReportModel)
    if report_type:
        query = query.filter(ReportModel.report_type == report_type)
    reports = query.order_by(ReportModel.created_at.desc()).offset(skip).limit(limit).all()
    return reports


@router.get("/{report_id}", response_model=Report)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    if current_user.role not in {UserRole.ADMIN.value, UserRole.AUDITOR.value}:
        raise HTTPException(status_code=403, detail="Admin or auditor access required")
    report = db.query(ReportModel).filter(ReportModel.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    if current_user.role != UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Admin access required")
    db_report = db.query(ReportModel).filter(ReportModel.id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    db.delete(db_report)
    db.commit()
    return None


@router.get("/types/list")
def get_report_types():
    return {
        "types": [
            "usage_summary",
            "policy_violations",
            "prompt_analysis",
            "system_health",
            "security"
        ]
    }


# =============================================================================
# Export Endpoints (Blueprint API)
# =============================================================================

@router.get("/export")
def export_audit_data(
    format: str = Query("csv", description="Export format: csv, json, pdf"),
    report_type: str = Query("usage", description="Type: usage, violations, all"),
    org_id: Optional[int] = None,
    days: int = Query(30, description="Number of days to export"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    GET /reporting/export - Pull audit data for dashboards or BI
    
    Query parameters (matching blueprint):
    - format: Export format (csv, json)
    - report_type: Type of data (usage, violations, all)
    - org_id: Filter by organization
    - days: Number of days to export (default 30)
    
    Returns exportable data for compliance (SOC2, ISO, internal audits).
    """
    start_date = datetime.now(tz=timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    if current_user.role not in {UserRole.ADMIN.value, UserRole.AUDITOR.value}:
        raise HTTPException(status_code=403, detail="Admin or auditor access required")
    if current_user.role != UserRole.ADMIN.value:
        if current_user.org_id is None:
            raise HTTPException(status_code=403, detail="Organization access required")
        if org_id and org_id != current_user.org_id:
            raise HTTPException(status_code=403, detail="Not authorized for this organization")
        org_id = current_user.org_id
    
    if report_type in ["usage", "all"]:
        # Get AI usage logs
        query = db.query(AIUsageLogModel).filter(
            AIUsageLogModel.timestamp >= start_date
        )
        if org_id:
            query = query.filter(AIUsageLogModel.org_id == org_id)
        
        usage_logs = query.order_by(AIUsageLogModel.timestamp.desc()).all()
    else:
        usage_logs = []
    
    if report_type in ["violations", "all"]:
        # Get policy violations
        query = db.query(PolicyViolationModel).filter(
            PolicyViolationModel.created_at >= start_date
        )
        
        if org_id:
            query = query.join(AIUsageLogModel).filter(
                AIUsageLogModel.org_id == org_id
            )
        
        violations = query.order_by(
            PolicyViolationModel.created_at.desc()
        ).all()
    else:
        violations = []
    
    # Track this export in audit_exports table for compliance
    total_records = len(usage_logs) + len(violations)
    db_audit_export = AuditExportModel(
        org_id=org_id,
        export_type=report_type,
        generated_by=current_user.id,
        filters={"format": format, "days": days},
        record_count=total_records
    )
    db.add(db_audit_export)
    db.commit()
    
    # Prepare data based on format
    if format == "csv":
        output = io.StringIO()
        
        if report_type == "usage" or report_type == "all":
            # CSV for usage logs
            writer = csv.writer(output)
            writer.writerow([
                "request_id", "org_id", "user_id", "tool_id", 
                "prompt_preview", "usage_type", "data_type", 
                "policy_result", "policy_message", "input_tokens",
                "output_tokens", "total_tokens", "cost_usd", "timestamp"
            ])
            
            for log in usage_logs:
                writer.writerow([
                    log.request_id,
                    log.org_id,
                    log.user_id,
                    log.tool_id,
                    log.prompt[:100] if log.prompt else "",  # Preview
                    log.usage_type,
                    log.data_type,
                    log.policy_result,
                    log.policy_message or "",
                    log.input_tokens,
                    log.output_tokens,
                    log.total_tokens,
                    log.cost_usd,
                    log.timestamp.isoformat() if log.timestamp else ""
                ])
            
            if report_type == "all":
                writer.writerow([])  # Empty row separator
                writer.writerow(["VIOLATIONS"])
                writer.writerow([
                    "id", "usage_id", "policy_id", "violation_type",
                    "severity", "details", "resolved", "created_at"
                ])
                
                for v in violations:
                    writer.writerow([
                        v.id,
                        v.usage_id,
                        v.policy_id,
                        v.violation_type,
                        v.severity,
                        v.details,
                        v.resolved,
                        v.created_at.isoformat() if v.created_at else ""
                    ])
        
        elif report_type == "violations":
            writer = csv.writer(output)
            writer.writerow([
                "id", "usage_id", "policy_id", "violation_type",
                "severity", "details", "resolved", "created_at"
            ])
            
            for v in violations:
                writer.writerow([
                    v.id,
                    v.usage_id,
                    v.policy_id,
                    v.violation_type,
                    v.severity,
                    v.details,
                    v.resolved,
                    v.created_at.isoformat() if v.created_at else ""
                ])
        
        output.seek(0)
        filename = f"guardrail_audit_{report_type}_{datetime.now(tz=timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}.csv"
        
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    
    elif format == "pdf":
        # Generate PDF report
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []
        
        # Title
        title = f"Guardrail AI Audit Report - {report_type.title()}"
        elements.append(Paragraph(title, styles['Title']))
        elements.append(Spacer(1, 12))
        
        # Metadata
        metadata = f"""
        Report Period: {days} days
        Generated: {datetime.now(tz=timezone.utc).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S UTC')}
        Organization ID: {org_id or 'All'}
        Total Records: {total_records}
        """
        elements.append(Paragraph(metadata, styles['Normal']))
        elements.append(Spacer(1, 12))
        
        if report_type in ["usage", "all"] and usage_logs:
            # Usage logs table
            elements.append(Paragraph("AI Usage Logs", styles['Heading2']))
            elements.append(Spacer(1, 6))
            
            usage_data = [["Request ID", "User ID", "Tool ID", "Usage Type", "Policy Result", "Tokens", "Cost", "Date"]]
            for log in usage_logs[:100]:  # Limit for PDF
                usage_data.append([
                    log.request_id[:8] + "..." if log.request_id else "",
                    str(log.user_id or ""),
                    str(log.tool_id or ""),
                    log.usage_type or "",
                    log.policy_result or "",
                    str(log.total_tokens or 0),
                    f"${log.cost_usd:.4f}" if log.cost_usd else "$0.00",
                    log.timestamp.strftime('%Y-%m-%d') if log.timestamp else ""
                ])
            
            usage_table = Table(usage_data)
            usage_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(usage_table)
            elements.append(Spacer(1, 12))
        
        if report_type in ["violations", "all"] and violations:
            # Violations table
            elements.append(Paragraph("Policy Violations", styles['Heading2']))
            elements.append(Spacer(1, 6))
            
            violation_data = [["ID", "Type", "Severity", "Details", "Date"]]
            for v in violations[:50]:  # Limit for PDF
                violation_data.append([
                    str(v.id),
                    v.violation_type or "",
                    v.severity or "",
                    v.details[:50] + "..." if v.details and len(v.details) > 50 else v.details or "",
                    v.created_at.strftime('%Y-%m-%d') if v.created_at else ""
                ])
            
            violation_table = Table(violation_data)
            violation_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(violation_table)
        
        doc.build(elements)
        buffer.seek(0)
        
        filename = f"guardrail_audit_{report_type}_{datetime.now(tz=timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}.pdf"
        return StreamingResponse(
            iter([buffer.getvalue()]),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    
    else:  # JSON format
        data = {
            "export_date": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(),
            "period_days": days,
            "report_type": report_type,
            "org_id": org_id,
            "usage_logs": [
                {
                    "request_id": log.request_id,
                    "org_id": log.org_id,
                    "user_id": log.user_id,
                    "tool_id": log.tool_id,
                    "prompt": log.prompt,
                    "usage_type": log.usage_type,
                    "data_type": log.data_type,
                    "policy_result": log.policy_result,
                    "policy_message": log.policy_message,
                    "input_tokens": log.input_tokens,
                    "output_tokens": log.output_tokens,
                    "total_tokens": log.total_tokens,
                    "cost_usd": log.cost_usd,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None
                }
                for log in usage_logs
            ],
            "violations": [
                {
                    "id": v.id,
                    "usage_id": v.usage_id,
                    "policy_id": v.policy_id,
                    "violation_type": v.violation_type,
                    "severity": v.severity,
                    "details": v.details,
                    "resolved": v.resolved,
                    "created_at": v.created_at.isoformat() if v.created_at else None
                }
                for v in violations
            ]
        }
        
        return data


@router.get("/export/formats")
def get_export_formats():
    """Get available export formats"""
    return {
        "formats": ["csv", "json", "pdf"],
        "report_types": ["usage", "violations", "all"]
    }
