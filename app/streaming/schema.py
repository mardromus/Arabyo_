"""Transaction event schema for Kafka — in-code validation (Pydantic)."""
from typing import Any, Optional
from pydantic import BaseModel, Field, AliasChoices


class TransactionEvent(BaseModel):
    """Schema for a single transaction event on transactions.incoming.
    Aligns with DB columns where possible (from_bank, from_account, amount_paid, etc.).
    """
    transaction_id: Optional[str] = None
    account_id: Optional[str] = None  # canonical e.g. from_bank_from_account for partitioning
    timestamp: str
    amount: float = Field(..., validation_alias=AliasChoices("amount", "amount_paid"))
    currency: str = Field(default="USD", validation_alias=AliasChoices("currency", "payment_currency"))
    from_bank: str = ""
    from_account: str = ""
    to_bank: str = ""
    to_account: str = ""
    payment_format: str = ""
    amount_received: Optional[float] = None
    receiving_currency: Optional[str] = None
    geo_location: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    class Config:
        populate_by_name = True
        extra = "ignore"

    def to_db_row(self):
        """Return dict suitable for INSERT into transactions table (id auto)."""
        return {
            "timestamp": self.timestamp,
            "from_bank": self.from_bank,
            "from_account": self.from_account,
            "to_bank": self.to_bank,
            "to_account": self.to_account,
            "amount_received": self.amount_received if self.amount_received is not None else 0,
            "receiving_currency": self.receiving_currency or self.currency,
            "amount_paid": self.amount,
            "payment_currency": self.currency,
            "payment_format": self.payment_format,
            "is_laundering": 0,
        }
