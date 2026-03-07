package services

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"log"
	"strings"
)

type RecordService struct{}

func NewRecordService() *RecordService {
	return &RecordService{}
}

func (s *RecordService) GetRecords(domainID string) []models.Record {
	rows, err := db.DB.Query("SELECT id, domain_id, name, type, content, ttl FROM records WHERE domain_id=? ORDER BY type", domainID)

	if err != nil {
		log.Println("SELECT record failed", err)
		return nil
	}

	defer rows.Close()

	var recs []models.Record
	for rows.Next() {
		var r models.Record
		if err := rows.Scan(&r.ID, &r.Domain_id, &r.Name, &r.Type, &r.Content, &r.Ttl); err != nil {
			log.Println("Row scan error:", err)
			continue
		}
		recs = append(recs, r)
	}
	if err := rows.Err(); err != nil {
		log.Println("Rows iteration error:", err)
		return nil
	}
	return recs
}

func (s *RecordService) UpdateRecord(id, name, rtype, content, ttl string) error {
	_, err := db.DB.Exec(
		"UPDATE records SET name=?, type=?, content=?, ttl=? WHERE id=?",
		normalizeRecordName(name),
		normalizeRecordType(rtype),
		strings.TrimSpace(content),
		strings.TrimSpace(ttl),
		id,
	)
	return err
}

func (s *RecordService) CreateRecord(
	domainID string,
	name string,
	recordType string,
	content string,
	ttl string,
) error {
	_, err := db.DB.Exec(`
		INSERT INTO records (domain_id, name, type, content, ttl)
		VALUES (?, ?, ?, ?, ?)
	`,
		domainID,
		normalizeRecordName(name),
		normalizeRecordType(recordType),
		strings.TrimSpace(content),
		strings.TrimSpace(ttl),
	)

	return err
}

func (s *RecordService) DeleteRecord(id string) error {
	_, err := db.DB.Exec(
		"DELETE FROM records WHERE id=?",
		id,
	)
	if err != nil {
		log.Println("DELETE record failed:", err)
	}
	return err
}

func normalizeRecordName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func normalizeRecordType(rtype string) string {
	return strings.ToUpper(strings.TrimSpace(rtype))
}
