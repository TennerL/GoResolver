package handlers

import (
	"html/template"
	"GoResolver/internal/services"
)

func baseFuncMap() template.FuncMap {
	settings := services.NewSettingsService()
	return template.FuncMap{
		"setting": func(key string) string {
			return settings.GetValue(key)
		},
	}
}

func mergeFuncMaps(maps ...template.FuncMap) template.FuncMap {
	merged := template.FuncMap{}
	for _, m := range maps {
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}

func parseTemplatesWithFuncMap(funcMap template.FuncMap, files ...string) *template.Template {
	return template.Must(template.New("layout.html").Funcs(funcMap).ParseFiles(files...))
}
