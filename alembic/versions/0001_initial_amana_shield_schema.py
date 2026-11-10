"""Initial AMANA SHIELD schema (8 core tables).

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-11-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. domains
    op.create_table(
        "domains",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("canonical_host", sa.String(length=255), nullable=False),
        sa.Column("registered_domain", sa.String(length=255), nullable=False),
        sa.Column("tld_suffix", sa.String(length=63), nullable=False),
        sa.Column(
            "is_idn_punycode",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "classification",
            sa.String(length=32),
            server_default=sa.text("'UNKNOWN'"),
            nullable=False,
        ),
        sa.Column("official_institution", sa.String(length=128), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'ACTIVE'"),
            nullable=False,
        ),
        sa.Column(
            "source",
            sa.String(length=128),
            server_default=sa.text("'SYSTEM_DISCOVERED'"),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("review_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewer", sa.String(length=128), nullable=True),
        sa.Column("domain_registered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("domain_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("registrar_name", sa.String(length=255), nullable=True),
        sa.Column(
            "dns_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("rdap_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("canonical_host", name="uq_domains_canonical_host"),
        sa.CheckConstraint(
            "classification IN ('OFFICIAL', 'BENIGN_KNOWN', 'UNKNOWN', 'SUSPICIOUS', 'MALICIOUS')",
            name="ck_domains_classification",
        ),
        sa.CheckConstraint(
            "classification != 'OFFICIAL' OR official_institution IS NOT NULL",
            name="ck_domains_official_requires_institution",
        ),
    )
    op.create_index("ix_domains_registered_domain", "domains", ["registered_domain"])
    op.create_index("ix_domains_classification", "domains", ["classification"])

    # 2. scam_campaigns
    op.create_table(
        "scam_campaigns",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("scam_category", sa.String(length=64), nullable=False),
        sa.Column("fingerprint_hash", sa.String(length=64), nullable=False),
        sa.Column("primary_domain_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'ACTIVE'"),
            nullable=False,
        ),
        sa.Column(
            "sighting_count",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["primary_domain_id"], ["domains.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug", name="uq_scam_campaigns_slug"),
        sa.UniqueConstraint(
            "fingerprint_hash", name="uq_scam_campaigns_fingerprint_hash"
        ),
        sa.CheckConstraint(
            "sighting_count >= 1", name="ck_scam_campaigns_sighting_positive"
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'MONITORING', 'ARCHIVED')",
            name="ck_scam_campaigns_status",
        ),
    )
    op.create_index(
        "ix_scam_campaigns_status_last_seen",
        "scam_campaigns",
        ["status", "last_seen_at"],
    )

    # 3. submissions
    op.create_table(
        "submissions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(length=32), nullable=False),
        sa.Column("external_message_id", sa.String(length=128), nullable=False),
        sa.Column("sender_hash", sa.String(length=64), nullable=False),
        sa.Column("raw_text", sa.Text(), nullable=False),
        sa.Column("normalised_text", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "extracted_urls",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "processing_status",
            sa.String(length=32),
            server_default=sa.text("'RECEIVED'"),
            nullable=False,
        ),
        sa.Column(
            "submitted_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(now() + interval '90 days')"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["scam_campaigns.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "external_message_id", name="uq_submissions_external_message_id"
        ),
        sa.CheckConstraint(
            "channel IN ('WHATSAPP', 'WEB', 'ANDROID_SHARE')",
            name="ck_submissions_channel",
        ),
        sa.CheckConstraint(
            "processing_status IN ('RECEIVED', 'PROCESSING', 'COMPLETED', 'FAILED')",
            name="ck_submissions_processing_status",
        ),
        sa.CheckConstraint(
            "length(raw_text) BETWEEN 1 AND 10000",
            name="ck_submissions_raw_text_len",
        ),
    )
    op.create_index(
        "ix_submissions_sender_hash_submitted_at",
        "submissions",
        ["sender_hash", "submitted_at"],
    )
    op.create_index(
        "ix_submissions_content_sha256", "submissions", ["content_sha256"]
    )
    op.create_index("ix_submissions_campaign_id", "submissions", ["campaign_id"])

    # 4. threat_indicators
    op.create_table(
        "threat_indicators",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("indicator_value", sa.String(length=2048), nullable=False),
        sa.Column("linked_domain_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "first_seen_submission_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("threat_category", sa.String(length=64), nullable=False),
        sa.Column(
            "confidence_level",
            sa.String(length=16),
            server_default=sa.text("'MEDIUM'"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'CANDIDATE'"),
            nullable=False,
        ),
        sa.Column("source_origin", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("reviewer", sa.String(length=128), nullable=True),
        sa.Column(
            "valid_from",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["linked_domain_id"], ["domains.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["first_seen_submission_id"], ["submissions.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "indicator_type",
            "indicator_value",
            name="uq_threat_indicators_type_value",
        ),
        sa.CheckConstraint(
            "indicator_type IN ('DOMAIN', 'URL', 'PHONE_NUMBER', 'BANK_ACCOUNT', 'TEXT_HASH')",
            name="ck_threat_indicators_type",
        ),
        sa.CheckConstraint(
            "status IN ('CANDIDATE', 'CONFIRMED', 'REVOKED', 'EXPIRED')",
            name="ck_threat_indicators_status",
        ),
        sa.CheckConstraint(
            "confidence_level IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_threat_indicators_confidence",
        ),
    )
    op.create_index(
        "ix_threat_indicators_active_lookup",
        "threat_indicators",
        ["indicator_type", "indicator_value", "status"],
    )

    # 5. evidence_sources
    op.create_table(
        "evidence_sources",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("institution_code", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("summary_content", sa.Text(), nullable=False),
        sa.Column("official_url", sa.String(length=2048), nullable=False),
        sa.Column(
            "is_debunking_notice",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column(
            "source_category",
            sa.String(length=32),
            server_default=sa.text("'GOVERNMENT_INSTITUTION'"),
            nullable=False,
        ),
        sa.Column(
            "verification_status",
            sa.String(length=32),
            server_default=sa.text("'VERIFIED_AUTHENTIC'"),
            nullable=False,
        ),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "search_vector",
            postgresql.TSVECTOR(),
            sa.Computed(
                "to_tsvector('english', coalesce(institution_code, '') || ' ' || "
                "coalesce(title, '') || ' ' || coalesce(summary_content, ''))",
                persisted=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("official_url", name="uq_evidence_sources_official_url"),
        sa.CheckConstraint(
            "source_type IN ('PRESS_RELEASE', 'OFFICIAL_PORTAL', 'DEBUNKING_NOTICE', 'POLICY_RULE')",
            name="ck_evidence_sources_source_type",
        ),
    )
    op.create_index(
        "ix_evidence_sources_search_vector",
        "evidence_sources",
        ["search_vector"],
        postgresql_using="gin",
    )
    op.create_index(
        "ix_evidence_sources_institution_active",
        "evidence_sources",
        ["institution_code", "is_active", "published_at"],
    )

    # 6. assessments
    op.create_table(
        "assessments",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("primary_domain_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("message_risk", sa.String(length=32), nullable=False),
        sa.Column("url_risk", sa.String(length=32), nullable=False),
        sa.Column("claim_verification_status", sa.String(length=32), nullable=False),
        sa.Column("public_verdict", sa.String(length=32), nullable=False),
        sa.Column("internal_status", sa.String(length=32), nullable=False),
        sa.Column(
            "triggered_rules",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "triage_findings",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "ai_heuristics",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("explanation_text", sa.Text(), nullable=False),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column(
            "is_degraded_mode",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "assessed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"], ["submissions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["primary_domain_id"], ["domains.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("submission_id", name="uq_assessments_submission_id"),
        sa.CheckConstraint(
            "message_risk IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_assessments_message_risk",
        ),
        sa.CheckConstraint(
            "url_risk IN ('NO_URL', 'VERIFIED_OFFICIAL', 'BENIGN_KNOWN', 'UNKNOWN', 'SUSPICIOUS', 'MALICIOUS')",
            name="ck_assessments_url_risk",
        ),
        sa.CheckConstraint(
            "claim_verification_status IN ('NOT_APPLICABLE', 'VERIFIED_OFFICIAL', 'CONTRADICTED_BY_OFFICIAL', 'OUTDATED_OR_EXPIRED', 'UNVERIFIED')",
            name="ck_assessments_claim_status",
        ),
        sa.CheckConstraint(
            "public_verdict IN ('MALICIOUS', 'SUSPICIOUS', 'OFFICIAL', 'UNVERIFIED')",
            name="ck_assessments_public_verdict",
        ),
        sa.CheckConstraint(
            "internal_status IN ('CONFIRMED', 'UNDER_REVIEW', 'DISMISSED')",
            name="ck_assessments_internal_status",
        ),
        sa.CheckConstraint(
            "NOT (is_degraded_mode = true AND public_verdict = 'OFFICIAL')",
            name="ck_assessments_no_official_when_degraded",
        ),
    )
    op.create_index(
        "ix_assessments_internal_status_assessed_at",
        "assessments",
        ["internal_status", "assessed_at"],
    )
    op.create_index("ix_assessments_public_verdict", "assessments", ["public_verdict"])

    # 7. extracted_claims
    op.create_table(
        "extracted_claims",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("claim_text", sa.Text(), nullable=False),
        sa.Column("impersonated_entity", sa.String(length=128), nullable=True),
        sa.Column("claim_topic", sa.String(length=64), nullable=False),
        sa.Column("verification_outcome", sa.String(length=32), nullable=False),
        sa.Column("matched_evidence_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "confidence",
            sa.String(length=16),
            server_default=sa.text("'MEDIUM'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"], ["assessments.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["matched_evidence_id"], ["evidence_sources.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "verification_outcome IN ('VERIFIED_OFFICIAL', 'CONTRADICTED_BY_OFFICIAL', 'OUTDATED_OR_EXPIRED', 'UNVERIFIED')",
            name="ck_extracted_claims_outcome",
        ),
        sa.CheckConstraint(
            "verification_outcome NOT IN ('VERIFIED_OFFICIAL', 'CONTRADICTED_BY_OFFICIAL') "
            "OR matched_evidence_id IS NOT NULL",
            name="ck_extracted_claims_verified_requires_source",
        ),
        sa.CheckConstraint(
            "confidence IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_extracted_claims_confidence",
        ),
    )
    op.create_index(
        "ix_extracted_claims_assessment_id", "extracted_claims", ["assessment_id"]
    )
    op.create_index(
        "ix_extracted_claims_matched_evidence_id",
        "extracted_claims",
        ["matched_evidence_id"],
    )

    # 8. review_events
    op.create_table(
        "review_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("threat_indicator_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_identifier", sa.String(length=128), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("previous_status", sa.String(length=64), nullable=False),
        sa.Column("new_status", sa.String(length=64), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"], ["assessments.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["threat_indicator_id"], ["threat_indicators.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "target_type IN ('ASSESSMENT', 'THREAT_INDICATOR')",
            name="ck_review_events_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'ASSESSMENT' AND assessment_id IS NOT NULL) OR "
            "(target_type = 'THREAT_INDICATOR' AND threat_indicator_id IS NOT NULL)",
            name="ck_review_events_target_link",
        ),
        sa.CheckConstraint(
            "length(trim(rationale)) >= 5",
            name="ck_review_events_rationale_nonempty",
        ),
    )
    op.create_index(
        "ix_review_events_assessment_id",
        "review_events",
        ["assessment_id", "created_at"],
    )
    op.create_index(
        "ix_review_events_threat_indicator_id",
        "review_events",
        ["threat_indicator_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_table("review_events")
    op.drop_table("extracted_claims")
    op.drop_table("assessments")
    op.drop_table("evidence_sources")
    op.drop_table("threat_indicators")
    op.drop_table("submissions")
    op.drop_table("scam_campaigns")
    op.drop_table("domains")
