"""
Test suite for Compliance Reporting Engine

Following TDD Red-Green-Refactor cycle with 100% test coverage requirement.
Tests written BEFORE implementation to ensure proper TDD compliance.

Enterprise compliance features:
- GDPR Article 30 data processing reports
- HIPAA security risk assessments  
- SOC 2 control evidence collection
- LaTeX PDF generation with digital signatures
- AWS KMS integration for report signing
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from datetime import datetime, timedelta, date
from pathlib import Path
import tempfile
import json

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from services.compliance_reporting import (
    ComplianceReportingService,
    GDPRReportGenerator,
    HIPAAAssessmentGenerator,
    SOC2EvidenceCollector,
    PDFReportService,
    ComplianceReport,
    ComplianceFramework,
    ReportStatus,
    ReportType,
    DateRange
)
from services.cache_service import CacheService


class TestComplianceReportingService:
    """Test Compliance Reporting Service with 100% coverage"""
    
    @pytest.fixture
    def mock_cache_service(self):
        """Mock cache service"""
        cache = MagicMock(spec=CacheService)
        cache.get = AsyncMock(return_value=None)
        cache.set = AsyncMock(return_value=True)
        return cache
    
    @pytest.fixture
    def mock_aws_kms_client(self):
        """Mock AWS KMS client for digital signatures"""
        kms_client = MagicMock()
        kms_client.sign = AsyncMock(return_value={
            'Signature': b'mock_signature_bytes',
            'KeyId': 'arn:aws:kms:us-east-1:123456789012:key/test-key'
        })
        return kms_client
    
    @pytest.fixture
    def compliance_service(self, mock_cache_service, mock_aws_kms_client):
        """Create compliance reporting service with mocked dependencies"""
        return ComplianceReportingService(
            cache_service=mock_cache_service,
            kms_client=mock_aws_kms_client,
            reports_storage_path="/tmp/compliance_reports",
            latex_templates_path="/tmp/latex_templates",
            enable_digital_signatures=True
        )
    
    def test_compliance_service_initialization(self, compliance_service):
        """Test compliance service initializes with correct configuration"""
        assert compliance_service.reports_storage_path == Path("/tmp/compliance_reports")
        assert compliance_service.latex_templates_path == Path("/tmp/latex_templates")
        assert compliance_service.enable_digital_signatures is True
        assert compliance_service.kms_client is not None
        assert compliance_service.cache_service is not None
        assert len(compliance_service.stats) > 0
    
    @pytest.mark.asyncio
    async def test_compliance_service_initialize_success(self, compliance_service):
        """Test successful compliance service initialization"""
        with patch('pathlib.Path.mkdir') as mock_mkdir:
            await compliance_service.initialize()
            
            # Should create necessary directories
            assert mock_mkdir.call_count >= 2  # reports and templates directories
            
            # Should initialize report generators
            assert compliance_service.gdpr_generator is not None
            assert compliance_service.hipaa_generator is not None
            assert compliance_service.soc2_collector is not None
            assert compliance_service.pdf_service is not None
    
    @pytest.mark.asyncio
    async def test_generate_gdpr_report_success(self, compliance_service):
        """Test successful GDPR compliance report generation"""
        # Set up test data
        start_date = date(2024, 1, 1)
        end_date = date(2024, 12, 31)
        organization_id = "test_org_123"
        
        # Mock GDPR generator
        compliance_service.gdpr_generator = MagicMock()
        compliance_service.gdpr_generator.generate_data_processing_report = AsyncMock(
            return_value={
                'processing_activities': [
                    {
                        'activity_id': 'activity_001',
                        'purpose': 'Threat Intelligence Processing',
                        'data_categories': ['IP addresses', 'Domain names'],
                        'legal_basis': 'Legitimate interest',
                        'retention_period': '48 hours',
                        'security_measures': ['Encryption', 'Access controls']
                    }
                ],
                'data_subjects': ['External threat actors', 'Network entities'],
                'recipients': ['Security team', 'IT administrators'],
                'transfers': []
            }
        )
        
        # Execute report generation
        report = await compliance_service.generate_gdpr_report(
            organization_id=organization_id,
            start_date=start_date,
            end_date=end_date
        )
        
        # Verify report
        assert isinstance(report, ComplianceReport)
        assert report.framework == ComplianceFramework.GDPR
        assert report.report_type == ReportType.DATA_PROCESSING_ACTIVITIES
        assert report.organization_id == organization_id
        assert report.status == ReportStatus.COMPLETED
        assert report.generated_at is not None
        assert len(report.content['processing_activities']) > 0
        
        # Verify generator was called with correct parameters
        compliance_service.gdpr_generator.generate_data_processing_report.assert_called_once_with(
            organization_id, start_date, end_date
        )
    
    @pytest.mark.asyncio
    async def test_generate_hipaa_assessment_success(self, compliance_service):
        """Test successful HIPAA security risk assessment"""
        covered_entity_id = "ce_healthcare_001"
        
        # Mock HIPAA generator
        compliance_service.hipaa_generator = MagicMock()
        compliance_service.hipaa_generator.generate_security_assessment = AsyncMock(
            return_value={
                'assessment_id': 'hipaa_assessment_001',
                'covered_entity': covered_entity_id,
                'security_controls': [
                    {
                        'control_id': '164.312(a)(1)',
                        'control_name': 'Access Control',
                        'status': 'COMPLIANT',
                        'evidence': ['User access logs', 'Role-based permissions'],
                        'recommendations': []
                    }
                ],
                'risk_level': 'LOW',
                'compliance_score': 95,
                'findings': [],
                'recommendations': ['Implement additional monitoring']
            }
        )
        
        # Execute assessment
        report = await compliance_service.generate_hipaa_assessment(
            covered_entity_id=covered_entity_id
        )
        
        # Verify assessment
        assert report.framework == ComplianceFramework.HIPAA
        assert report.report_type == ReportType.SECURITY_ASSESSMENT
        assert report.organization_id == covered_entity_id
        assert report.content['compliance_score'] == 95
        assert report.content['risk_level'] == 'LOW'
        
        # Verify statistics
        assert compliance_service.stats['reports_generated'] == 1
        assert compliance_service.stats['hipaa_assessments'] == 1
    
    @pytest.mark.asyncio
    async def test_generate_soc2_evidence_success(self, compliance_service):
        """Test successful SOC 2 control evidence collection"""
        control_id = "CC6.1"  # Common Criteria 6.1
        date_range = DateRange(
            start_date=date(2024, 1, 1),
            end_date=date(2024, 3, 31)
        )
        organization_id = "soc2_org_001"
        
        # Mock SOC 2 collector
        compliance_service.soc2_collector = MagicMock()
        compliance_service.soc2_collector.collect_control_evidence = AsyncMock(
            return_value={
                'control_id': control_id,
                'control_name': 'Logical and Physical Access Controls',
                'evidence_items': [
                    {
                        'evidence_id': 'ev_001',
                        'type': 'LOG_ANALYSIS',
                        'description': 'Access control logs review',
                        'collection_date': datetime.now(),
                        'evidence_data': {'failed_logins': 0, 'unauthorized_access': 0}
                    }
                ],
                'testing_results': {
                    'tests_performed': 5,
                    'tests_passed': 5,
                    'tests_failed': 0,
                    'effectiveness': 'EFFECTIVE'
                }
            }
        )
        
        # Execute evidence collection
        report = await compliance_service.generate_soc2_evidence(
            organization_id=organization_id,
            control_id=control_id,
            date_range=date_range
        )
        
        # Verify evidence report
        assert report.framework == ComplianceFramework.SOC2
        assert report.report_type == ReportType.CONTROL_EVIDENCE
        assert len(report.content['evidence_items']) > 0
        assert report.content['testing_results']['effectiveness'] == 'EFFECTIVE'
    
    @pytest.mark.asyncio
    async def test_generate_pdf_report_with_signature(self, compliance_service):
        """Test PDF generation with digital signature"""
        # Create test report
        report = ComplianceReport(
            report_id="test_pdf_001",
            framework=ComplianceFramework.GDPR,
            report_type=ReportType.DATA_PROCESSING_ACTIVITIES,
            organization_id="test_org",
            status=ReportStatus.COMPLETED,
            content={'test': 'data'}
        )
        
        # Mock PDF service
        compliance_service.pdf_service = MagicMock()
        compliance_service.pdf_service.generate_compliance_pdf = AsyncMock(
            return_value=b'mock_pdf_content'
        )
        compliance_service.pdf_service.sign_pdf_digitally = AsyncMock(
            return_value=b'mock_signed_pdf_content'
        )
        
        # Generate PDF
        pdf_content = await compliance_service.generate_pdf_report(report)
        
        # Verify PDF generation
        assert pdf_content == b'mock_signed_pdf_content'
        compliance_service.pdf_service.generate_compliance_pdf.assert_called_once()
        compliance_service.pdf_service.sign_pdf_digitally.assert_called_once_with(
            b'mock_pdf_content'
        )
        
        # Verify statistics
        assert compliance_service.stats['pdfs_generated'] == 1
        assert compliance_service.stats['reports_signed'] == 1
    
    @pytest.mark.asyncio
    async def test_generate_pdf_without_signature(self, compliance_service):
        """Test PDF generation without digital signature"""
        # Disable digital signatures
        compliance_service.enable_digital_signatures = False
        
        report = ComplianceReport(
            report_id="test_pdf_002",
            framework=ComplianceFramework.HIPAA,
            report_type=ReportType.SECURITY_ASSESSMENT,
            organization_id="test_org",
            status=ReportStatus.COMPLETED,
            content={'test': 'data'}
        )
        
        # Mock PDF service
        compliance_service.pdf_service = MagicMock()
        compliance_service.pdf_service.generate_compliance_pdf = AsyncMock(
            return_value=b'mock_unsigned_pdf'
        )
        
        # Generate PDF
        pdf_content = await compliance_service.generate_pdf_report(report)
        
        # Verify unsigned PDF
        assert pdf_content == b'mock_unsigned_pdf'
        compliance_service.pdf_service.generate_compliance_pdf.assert_called_once()
        
        # Should not call signing
        assert not hasattr(compliance_service.pdf_service, 'sign_pdf_digitally') or \
               compliance_service.pdf_service.sign_pdf_digitally.call_count == 0
    
    @pytest.mark.asyncio
    async def test_store_report_success(self, compliance_service):
        """Test successful report storage"""
        report = ComplianceReport(
            report_id="test_store_001",
            framework=ComplianceFramework.SOC2,
            report_type=ReportType.CONTROL_EVIDENCE,
            organization_id="test_org",
            status=ReportStatus.COMPLETED,
            content={'stored': 'data'}
        )
        
        # Mock file operations
        with patch('builtins.open', mock_open()) as mock_file:
            await compliance_service.store_report(report)
            
            # Verify file was written
            mock_file.assert_called_once()
            
            # Verify caching
            compliance_service.cache_service.set.assert_called()
        
        # Verify statistics
        assert compliance_service.stats['reports_stored'] == 1
    
    @pytest.mark.asyncio
    async def test_retrieve_report_from_cache(self, compliance_service):
        """Test report retrieval from cache"""
        report_id = "cached_report_001"
        
        # Mock cached report data
        compliance_service.cache_service.get = AsyncMock(return_value={
            'report_id': report_id,
            'framework': 'GDPR',
            'report_type': 'data_processing_activities',
            'organization_id': 'test_org',
            'status': 'completed',
            'content': {'cached': 'data'},
            'generated_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=30)).isoformat()
        })
        
        # Retrieve report
        report = await compliance_service.get_report(report_id)
        
        # Verify report
        assert report is not None
        assert report.report_id == report_id
        assert report.framework == ComplianceFramework.GDPR
        
        # Verify cache hit
        assert compliance_service.stats['cache_hits'] == 1
    
    @pytest.mark.asyncio
    async def test_retrieve_report_from_storage(self, compliance_service):
        """Test report retrieval from file storage"""
        report_id = "stored_report_001"
        
        # Mock no cache hit
        compliance_service.cache_service.get = AsyncMock(return_value=None)
        
        # Mock file content
        report_data = {
            'report_id': report_id,
            'framework': 'HIPAA',
            'report_type': 'security_assessment',
            'organization_id': 'test_org',
            'status': 'completed',
            'content': {'file': 'data'},
            'generated_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=365)).isoformat()
        }
        
        with patch('builtins.open', mock_open(read_data=json.dumps(report_data))):
            with patch('pathlib.Path.exists', return_value=True):
                report = await compliance_service.get_report(report_id)
        
        # Verify report
        assert report is not None
        assert report.report_id == report_id
        assert report.framework == ComplianceFramework.HIPAA
        
        # Verify cache miss and file read
        assert compliance_service.stats['cache_misses'] == 1
    
    @pytest.mark.asyncio
    async def test_list_reports_by_organization(self, compliance_service):
        """Test listing reports by organization"""
        organization_id = "test_org_list"
        
        # Mock multiple reports in cache/storage
        mock_reports = [
            {
                'report_id': 'report_001',
                'framework': 'GDPR',
                'organization_id': organization_id,
                'generated_at': datetime.now().isoformat()
            },
            {
                'report_id': 'report_002', 
                'framework': 'HIPAA',
                'organization_id': organization_id,
                'generated_at': (datetime.now() - timedelta(days=1)).isoformat()
            }
        ]
        
        with patch.object(compliance_service, '_scan_reports_storage', 
                         return_value=mock_reports):
            reports = await compliance_service.list_reports(
                organization_id=organization_id
            )
        
        # Verify report list
        assert len(reports) == 2
        assert all(r['organization_id'] == organization_id for r in reports)
        
        # Should be sorted by generation date (newest first)
        assert reports[0]['report_id'] == 'report_001'
        assert reports[1]['report_id'] == 'report_002'
    
    @pytest.mark.asyncio
    async def test_schedule_recurring_report(self, compliance_service):
        """Test scheduling recurring compliance reports"""
        schedule_config = {
            'organization_id': 'recurring_org',
            'framework': ComplianceFramework.GDPR,
            'report_type': ReportType.DATA_PROCESSING_ACTIVITIES,
            'frequency': 'monthly',  # monthly, quarterly, annually
            'next_run': datetime.now() + timedelta(days=30)
        }
        
        # Mock scheduling
        with patch('asyncio.create_task') as mock_create_task:
            schedule_id = await compliance_service.schedule_recurring_report(
                **schedule_config
            )
        
        # Verify scheduling
        assert schedule_id is not None
        assert schedule_id in compliance_service.scheduled_reports
        mock_create_task.assert_called_once()
        
        # Verify statistics
        assert compliance_service.stats['scheduled_reports'] == 1
    
    @pytest.mark.asyncio
    async def test_compliance_dashboard_metrics(self, compliance_service):
        """Test compliance dashboard metrics generation"""
        organization_id = "metrics_org"
        
        # Set up test statistics
        compliance_service.stats.update({
            'reports_generated': 50,
            'gdpr_reports': 20,
            'hipaa_assessments': 15,
            'soc2_evidence': 15,
            'pdfs_generated': 45,
            'reports_signed': 40,
            'compliance_score_avg': 87.5
        })
        
        # Mock list_reports to return test data
        mock_reports = []
        for i in range(50):
            if i < 20:
                framework = 'GDPR'
            elif i < 35:
                framework = 'HIPAA'
            else:
                framework = 'SOC2'
                
            mock_reports.append({
                'report_id': f'report_{i:03d}',
                'framework': framework,
                'report_type': 'test_type',
                'organization_id': organization_id,
                'status': 'completed',
                'generated_at': datetime.now().isoformat()
            })
        
        with patch.object(compliance_service, 'list_reports', return_value=mock_reports):
            # Generate dashboard metrics
            metrics = await compliance_service.get_compliance_dashboard(organization_id)
        
        # Verify metrics
        assert metrics['total_reports'] == 50
        assert metrics['reports_by_framework']['GDPR'] == 20
        assert metrics['reports_by_framework']['HIPAA'] == 15
        assert metrics['reports_by_framework']['SOC2'] == 15
        assert metrics['average_compliance_score'] == 87.5
        assert metrics['digital_signature_rate'] == 88.9  # 40/45
        assert 'recent_reports' in metrics
    
    def test_get_statistics(self, compliance_service):
        """Test statistics reporting"""
        # Set test statistics
        compliance_service.stats.update({
            'reports_generated': 100,
            'gdpr_reports': 40,
            'hipaa_assessments': 35,
            'soc2_evidence': 25,
            'pdfs_generated': 95,
            'reports_signed': 90,
            'reports_stored': 100,
            'cache_hits': 250,
            'cache_misses': 50
        })
        
        stats = compliance_service.get_statistics()
        
        assert stats['reports_generated'] == 100
        assert stats['success_rate'] == 95.0  # 95/100 PDFs generated
        assert stats['signature_rate'] == 94.7  # 90/95 signed
        assert stats['cache_hit_rate'] == 83.3  # 250/300
        assert 'reports_storage_path' in stats
        assert 'enable_digital_signatures' in stats
    
    @pytest.mark.asyncio
    async def test_service_shutdown(self, compliance_service):
        """Test service shutdown cleanup"""
        # Add some scheduled tasks
        compliance_service.scheduled_reports['test_task'] = MagicMock()
        compliance_service.scheduled_reports['test_task'].cancel = MagicMock()
        
        # Shutdown service
        await compliance_service.shutdown()
        
        # Verify cleanup
        compliance_service.scheduled_reports['test_task'].cancel.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])