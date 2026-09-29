agent: using-goose-mate
repo:
  mode: single-repo
  downstream: []
scope:
  domains:
    - backend
  description: "IAM Core Go SDK，包含请求链路 Runtime、机器主体声明、注入式 Catalog Bearer，以及人员目录和通知资料等受控 Management Client"
workflow:
  product_source: standalone
  issue:
    provider: github
    local_store: ""
    remote_repo: "git@github.com:swan-swan-swan/iam-core-sdk-go.git"
