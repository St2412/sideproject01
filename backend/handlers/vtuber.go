package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"encoding/base64"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

// VTuber 数据结构
type VTuber struct {
	VTuberID         int    `json:"vtuber_id"`
	VTuberName       string `json:"vtuber_name"`
	ChannelURL       string `json:"channel_url"`
	DebutDate        string `json:"debut_date"`
	Description      string `json:"description"`
	TotalSubscribers int    `json:"total_subscribers"`
	CompanyID        int    `json:"company_id"`
	Picture          []byte `json:"picture"`
	RecentVideo      string `json:"recent_video"`
}

// 获取所有 VTuber
func GetAllVTubersHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := DB.Query("SELECT * FROM VTuber")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var vtubers []VTuber
	for rows.Next() {
		var vtuber VTuber
		var picture []byte
		if err := rows.Scan(&vtuber.VTuberID, &vtuber.VTuberName, &vtuber.ChannelURL, &vtuber.DebutDate, &vtuber.Description, &vtuber.TotalSubscribers, &vtuber.CompanyID, &picture, &vtuber.RecentVideo); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		vtuber.Picture = picture
		vtubers = append(vtubers, vtuber)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vtubers)
}

// 获取單个 VTuber
func GetVTuberHandler(w http.ResponseWriter, r *http.Request) {
	vtuberID := r.URL.Query().Get("id")
	if vtuberID == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	var vtuber VTuber
	var picture []byte
	err := DB.QueryRow("SELECT * FROM VTuber WHERE VTuberID = ?", vtuberID).Scan(&vtuber.VTuberID, &vtuber.VTuberName, &vtuber.ChannelURL, &vtuber.DebutDate, &vtuber.Description, &vtuber.TotalSubscribers, &vtuber.CompanyID, &picture, &vtuber.RecentVideo)
	if err == sql.ErrNoRows {
		http.Error(w, "VTuber not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vtuber.Picture = picture

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vtuber)
}

// 创建 VTuber
func CreateVTuberHandler(w http.ResponseWriter, r *http.Request) {
	var vtuber VTuber
	err := json.NewDecoder(r.Body).Decode(&vtuber)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// 验证并解析日期
	_, err = time.Parse("2006-01-02", vtuber.DebutDate)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid date format: %v", err), http.StatusBadRequest)
		return
	}

	result, err := DB.Exec("INSERT INTO VTuber (VTuberName, ChannelURL, DebutDate, Description, TotalSubscribers, CompanyID, Picture, RecentVideo) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		vtuber.VTuberName, vtuber.ChannelURL, vtuber.DebutDate, vtuber.Description, vtuber.TotalSubscribers, vtuber.CompanyID, vtuber.Picture, vtuber.RecentVideo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vtuber.VTuberID = int(id)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(vtuber)
}

// 更新 VTuber
func UpdateVTuberHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	vtuberID := vars["id"]
	if vtuberID == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	var vtuber VTuber
	err := json.NewDecoder(r.Body).Decode(&vtuber)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 验证并解析日期
	_, err = time.Parse("2006-01-02", vtuber.DebutDate)
	if err != nil {
		http.Error(w, "Invalid date format: "+vtuber.DebutDate, http.StatusBadRequest)
		return
	}

	// 将 Picture 从 []byte 转换为 string，然后进行 Base64 解码
	pictureString := string(vtuber.Picture)
	pictureData, err := base64.StdEncoding.DecodeString(pictureString)
	if err != nil {
		http.Error(w, "Invalid base64 data: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err = DB.Exec("UPDATE VTuber SET VTuberName = ?, ChannelURL = ?, DebutDate = ?, Description = ?, TotalSubscribers = ?, CompanyID = ?, Picture = ?, RecentVideo = ? WHERE VTuberID = ?",
		vtuber.VTuberName, vtuber.ChannelURL, vtuber.DebutDate, vtuber.Description, vtuber.TotalSubscribers, vtuber.CompanyID, pictureData, vtuber.RecentVideo, vtuberID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vtuber)
}

// 删除 VTuber
func DeleteVTuberHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	vtuberID := vars["id"]
	if vtuberID == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	_, err := DB.Exec("DELETE FROM VTuber WHERE VTuberID = ?", vtuberID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("VTuber deleted successfully")
	w.WriteHeader(http.StatusNoContent) // 204 No Content
}
