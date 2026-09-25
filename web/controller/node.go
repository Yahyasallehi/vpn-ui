package controller

import (
	"strconv"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
)

// NodeController manages the node registry: an address book of independent, unmodified
// remote vpn-ui installations this panel polls for status and may send a small set of
// safe actions to. See database/model.Node and web/service/node.go for the full scope
// statement - in particular, this NEVER pushes configuration to a node.
type NodeController struct {
	BaseController
	nodeService service.NodeService
}

// NewNodeController creates a new NodeController and initializes its routes.
func NewNodeController(g *gin.RouterGroup) *NodeController {
	a := &NodeController{}
	a.initRouter(g)
	return a
}

func (a *NodeController) initRouter(g *gin.RouterGroup) {
	g.GET("/list", a.list)
	g.POST("/add", a.add)
	g.POST("/update/:id", a.update)
	g.POST("/del/:id", a.del)
	g.POST("/:id/refresh", a.refresh)
	g.POST("/:id/restartXray", a.restartXray)
}

// list returns every registered node. EncryptedPassword is json:"-" on the model, so
// the stored credential never reaches the browser.
func (a *NodeController) list(c *gin.Context) {
	nodes, err := a.nodeService.ListNodes()
	jsonObj(c, nodes, err)
}

// nodeForm is the add/update request shape. Password is intentionally plain-text
// in the request body (submitted once, over the admin's own already-authenticated
// HTTPS session, exactly like any other credential field this panel accepts) and is
// encrypted at rest by NodeService before it ever reaches the database.
type nodeForm struct {
	Name     string `json:"name" form:"name"`
	BaseURL  string `json:"baseUrl" form:"baseUrl"`
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
	Enabled  bool   `json:"enabled" form:"enabled"`
}

func (a *NodeController) add(c *gin.Context) {
	var form nodeForm
	if err := c.ShouldBind(&form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.invalidFormData"), err)
		return
	}
	node := &model.Node{
		Name:     form.Name,
		BaseURL:  form.BaseURL,
		Username: form.Username,
		Enabled:  form.Enabled,
	}
	err := a.nodeService.CreateNode(node, form.Password)
	jsonMsgObj(c, I18nWeb(c, "pages.nodes.toasts.added"), node, err)
}

func (a *NodeController) update(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.invalidId"), err)
		return
	}
	var form nodeForm
	if err := c.ShouldBind(&form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.invalidFormData"), err)
		return
	}
	err = a.nodeService.UpdateNode(id, form.Name, form.BaseURL, form.Username, form.Password, form.Enabled)
	jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.updated"), err)
}

func (a *NodeController) del(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.invalidId"), err)
		return
	}
	err = a.nodeService.DeleteNode(id)
	jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.deleted"), err)
}

// refresh polls one node on demand, bypassing the 30s background cadence, and
// returns the freshly-cached row so the UI can update without a second /list call.
func (a *NodeController) refresh(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.invalidId"), err)
		return
	}
	node, err := a.nodeService.GetNode(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.notFound"), err)
		return
	}
	pollErr := a.nodeService.PollNode(node)
	// Re-read regardless of pollErr: PollNode persists LastError on failure too, and
	// the UI wants that message either way, not just on success.
	refreshed, err := a.nodeService.GetNode(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.notFound"), err)
		return
	}
	jsonMsgObj(c, I18nWeb(c, "pages.nodes.toasts.refreshed"), refreshed, pollErr)
}

// restartXray proxies the one write action v1 allows: restarting Xray on the node.
func (a *NodeController) restartXray(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.invalidId"), err)
		return
	}
	node, err := a.nodeService.GetNode(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.notFound"), err)
		return
	}
	err = a.nodeService.RestartRemoteXray(node)
	jsonMsg(c, I18nWeb(c, "pages.nodes.toasts.restarted"), err)
}
