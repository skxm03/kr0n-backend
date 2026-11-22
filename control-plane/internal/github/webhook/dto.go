package webhook

// InstallationEventPayload models GitHub's `installation` webhook event payload.
type InstallationEventPayload struct {
	Action       string `json:"action"`
	Installation struct {
		ID                  int64   `json:"id"`
		RepositorySelection string  `json:"repository_selection"`
		SuspendedAt         *string `json:"suspended_at"`
		Account             struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
	} `json:"installation"`
	Sender struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"sender"`
}

// InstallationRepositoriesEventPayload models GitHub's `installation_repositories` webhook event payload.
type InstallationRepositoriesEventPayload struct {
	Action              string     `json:"action"`
	RepositorySelection string     `json:"repository_selection"`
	Installation        struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	RepositoriesAdded   []RepoItem `json:"repositories_added"`
	RepositoriesRemoved []RepoItem `json:"repositories_removed"`
	Sender              struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"sender"`
}

// RepoItem represents a repository reference inside an installation_repositories webhook event.
type RepoItem struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}
