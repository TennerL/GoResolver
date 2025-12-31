package services 

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"log"
)

type RecordService struct{}

func NewRecordService() *RecordService {
	return &RecordService{}
}

func (s *RecordService) GetRecords(domain_id string) []models.Record {
	rows, err := db.DB.Query("SELECT id, domain_id, name, type, content, ttl FROM records WHERE domain_id=? ORDER BY type",domain_id)

	if err != nil {
		log.Println("SELECT record failed", err)
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
	return recs
}

func (s *RecordService) UpdateRecord(id, name, rtype, content, ttl string,) error {
	_, err := db.DB.Exec("UPDATE records SET name=?, type=?, content=?, ttl=? WHERE id=?", name, rtype, content, ttl, id,)
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
	`, domainID, name, recordType, content, ttl)

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