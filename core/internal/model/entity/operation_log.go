package entity

type OperationLog struct {
	Id       int64  `json:"id"        db:"id"`
	UserId   int64  `json:"user_id"   db:"user_id"`
	Type     string `json:"type"      db:"type"`
	Log      string `json:"log"       db:"log"`
	Ip       string `json:"ip"        db:"ip"`
	Info     string `json:"info"      db:"info"`
	AddTime  int64  `json:"addtime"   db:"addtime"`
	UserName string `json:"username"  db:"-"`
}
