package database_initialization

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
)

// Automatically adding table fields
func AddColumnIfNotExists(table, column, columnType, defaultValue string, notNull bool) error {
	notNullStr := ""
	if notNull {
		notNullStr = "NOT NULL"
	}
	defaultStr := ""
	if defaultValue != "" {
		defaultStr = "DEFAULT " + defaultValue
	}
	sql := fmt.Sprintf(`
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM information_schema.columns 
		WHERE table_name = '%s' AND column_name = '%s'
	) THEN
		ALTER TABLE %s ADD COLUMN %s %s %s %s;
	END IF;
END $$;`, table, column, table, column, columnType, notNullStr, defaultStr)
	_, err := g.DB().Exec(context.Background(), sql)
	if err != nil {
		g.Log().Error(context.Background(), "Failed to add column:", err, sql)
	}
	return err
}

func DropForeignKeyIfExists(table, column string) error {
	sql := fmt.Sprintf(`
DO $$
DECLARE
    constraint_name text;
BEGIN
    SELECT tc.constraint_name INTO constraint_name
    FROM information_schema.table_constraints tc
    JOIN information_schema.key_column_usage kcu
      ON tc.constraint_name = kcu.constraint_name
     AND tc.table_schema = kcu.table_schema
    WHERE tc.constraint_type = 'FOREIGN KEY'
      AND tc.table_name = '%s'
      AND kcu.column_name = '%s'
    LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %%I;', constraint_name);
    END IF;
END $$;
`, table, column, table)

	_, err := g.DB().Exec(context.Background(), sql)
	if err != nil {
		g.Log().Error(context.Background(), "Failed to drop foreign key:", err, sql)
	}
	return err
}
