package job

import (
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

// PollNodesJob refreshes every enabled Node's cached status on a timer, so the Nodes
// page reads from the DB and never blocks on a remote panel while the operator has it
// open. See web/service/node.go for what a poll actually does.
//
// It never blocks startup and never panics the cron runner: every per-node failure is
// caught by NodeService.PollNode itself (which writes it to that node's LastError) and
// is only logged here, not propagated.
type PollNodesJob struct {
	nodeService service.NodeService
}

// NewPollNodesJob creates a new PollNodesJob.
func NewPollNodesJob() *PollNodesJob {
	return &PollNodesJob{}
}

func (j *PollNodesJob) Run() {
	nodes, err := j.nodeService.ListEnabledNodes()
	if err != nil {
		logger.Warning("poll nodes: listing enabled nodes: ", err)
		return
	}
	// Sequential, not parallel: v1 expects a handful of nodes, and sequential keeps
	// this from becoming a thundering herd against the master's own outbound
	// connection limits. Revisit if node counts grow enough for 30s-per-node
	// latency to matter.
	for i := range nodes {
		if err := j.nodeService.PollNode(&nodes[i]); err != nil {
			// Already recorded on the node's own LastError column; this log line is
			// for the panel's own operator, not the Nodes page.
			logger.Warningf("poll nodes: node %d (%s): %v", nodes[i].Id, nodes[i].Name, err)
		}
	}
}
