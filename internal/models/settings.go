package models

type SettingItem struct {
	Key   string
	Label string
	Value string
	Group string
	Help  string
}

type SettingsPageData struct {
	Items []SettingItem
	Saved bool
}
