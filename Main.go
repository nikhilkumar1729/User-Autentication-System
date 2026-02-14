package main

import (
	"net/http"
	"strconv"
	"github.com/gin-gonic/gin"
	"distributed-task-queue-go/internal"
)

func main() {
	internal.InitDB()
	internal.InitRedis()

	r := gin.Default()

	// Create a new task
	r.POST("/tasks", func(c *gin.Context) {
		var input struct {
			Number int `json:"number"`
		}

		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		task := internal.Task{Status: "PENDING"}
		internal.DB.Create(&task)
		internal.RDB.LPush(internal.Ctx, "task_queue", task.ID)

		c.JSON(http.StatusOK, gin.H{
			"task_id": task.ID,
			"status":  "PENDING",
		})
	})

	// Get task status
	r.GET("/tasks/:id", func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		var task internal.Task
		internal.DB.First(&task, id)
		c.JSON(http.StatusOK, task)
	})

	r.Run(":8000")
}
