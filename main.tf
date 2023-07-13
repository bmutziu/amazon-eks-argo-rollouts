provider "aws" {
  region = local.region
}

provider "kubernetes" {
  host                   = module.eks_blueprints.eks_cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks_blueprints.eks_cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

data "aws_eks_cluster_auth" "this" {
  name = module.eks_blueprints.eks_cluster_id
}

data "aws_availability_zones" "available" {}

locals {
  name         = basename(path.cwd)
  cluster_name = coalesce(var.cluster_name, local.name)
  region       = "eu-west-2"

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
}

module "eks_blueprints" {
  source = "github.com/aws-ia/terraform-aws-eks-blueprints?ref=v4.27.0"

  cluster_name    = local.cluster_name
  cluster_version = "1.27"

  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnets

  managed_node_groups = {
    mg_5 = {
      node_group_name = "managed-ondemand"
      instance_types  = ["m5.large"]
      min_size        = 3
      subnet_ids      = module.vpc.private_subnets
    }
  }
}

module "eks_blueprints_kubernetes_addons" {
  source = "github.com/aws-ia/terraform-aws-eks-blueprints//modules/kubernetes-addons?ref=v4.27.0"

  eks_cluster_id       = module.eks_blueprints.eks_cluster_id
  eks_cluster_endpoint = module.eks_blueprints.eks_cluster_endpoint
  eks_oidc_provider    = module.eks_blueprints.oidc_provider
  eks_cluster_version  = module.eks_blueprints.eks_cluster_version

  # EKS Managed Add-ons
  enable_amazon_eks_vpc_cni = true # default is false
  #Optional
  amazon_eks_vpc_cni_config = {
    addon_name = "vpc-cni"
    # addon_version          = data.aws_eks_addon_version.latest["vpc-cni"].version
    addon_version            = "v1.13.2-eksbuild.1"
    service_account          = "aws-node"
    resolve_conflicts        = "OVERWRITE"
    namespace                = "kube-system"
    service_account_role_arn = ""
    preserve                 = true
    additional_iam_policies  = []
    tags                     = {}
  }
  enable_amazon_eks_coredns = true # default is false
  #Optional
  amazon_eks_coredns_config = {
    addon_name               = "coredns"
    addon_version            = "v1.10.1-eksbuild.2"
    service_account          = "coredns"
    resolve_conflicts        = "OVERWRITE"
    namespace                = "kube-system"
    service_account_role_arn = ""
    additional_iam_policies  = []
    tags                     = {}
  }
  enable_amazon_eks_kube_proxy = true # default is false
  #Optional
  amazon_eks_kube_proxy_config = {
    addon_name               = "kube-proxy"
    addon_version            = "v1.27.3-eksbuild.1"
    service_account          = "kube-proxy"
    resolve_conflicts        = "OVERWRITE"
    namespace                = "kube-system"
    additional_iam_policies  = []
    service_account_role_arn = ""
    tags                     = {}
  }

  # Add-ons
  enable_aws_load_balancer_controller = false
  enable_aws_cloudwatch_metrics       = false
  enable_aws_for_fluentbit            = false
  enable_cert_manager                 = false
  enable_cluster_autoscaler           = false
  enable_ingress_nginx                = false
  enable_keda                         = false
  enable_metrics_server               = false
  enable_prometheus                   = true
  enable_traefik                      = false
  enable_vpa                          = false
  enable_yunikorn                     = false
  enable_argo_rollouts                = true
  enable_grafana                      = true
  grafana_irsa_policies               = [] # Optional to add additional policies to IRSA
  # Optional grafana_helm_config
  grafana_helm_config = {
    name        = "grafana"
    chart       = "grafana"
    repository  = "https://grafana.github.io/helm-charts"
    version     = "6.43.1"
    namespace   = "grafana"
    description = "Grafana Helm Chart deployment configuration"
    values      = [templatefile("${path.module}/values.yaml", {})]
  }
  enable_appmesh_controller = true

  enable_amazon_eks_aws_ebs_csi_driver = true # default is false
  #Optional
  amazon_eks_aws_ebs_csi_driver_config = {
    addon_name               = "aws-ebs-csi-driver"
    addon_version            = "v1.20.0-eksbuild.1"
    service_account          = "ebs-csi-controller-sa"
    resolve_conflicts        = "OVERWRITE"
    namespace                = "kube-system"
    additional_iam_policies  = []
    service_account_role_arn = ""
    tags                     = {}
  }
}

module "irsa_app-envoy-proxies" {

  source                      = "github.com/aws-ia/terraform-aws-eks-blueprints//modules/irsa?ref=v4.27.0"
  kubernetes_namespace        = "app"
  create_kubernetes_namespace = true
  kubernetes_service_account  = "app-envoy-proxies"
  irsa_iam_policies           = [aws_iam_policy.appmesh_envoy.arn]
  eks_cluster_id              = module.eks_blueprints.eks_cluster_id
  eks_oidc_provider_arn       = module.eks_blueprints.eks_oidc_provider_arn

  depends_on = [module.eks_blueprints_kubernetes_addons]
}

resource "aws_iam_policy" "appmesh_envoy" {
  name_prefix = "appmesh-envoy"
  policy      = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Effect": "Allow",
          "Action": [
              "appmesh:StreamAggregatedResources",
              "appmesh:*",
              "xray:*"
          ],
          "Resource": "*"
      },
      {
          "Effect": "Allow",
          "Action": [
              "acm:ExportCertificate",
              "acm-pca:GetCertificateAuthorityCertificate"
          ],
          "Resource": "*"
      },
      {
        "Action": [
          "logs:*"
        ],
        "Effect": "Allow",
        "Resource": "*"
      }
  ]
}
  POLICY
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 4.0"

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.name}-default" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.name}-default" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.name}-default" }

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = 1
  }
}

#---------------------------------------------------------------
# ECR Resources
#---------------------------------------------------------------

resource "aws_ecr_repository" "demo-app" {
  name                 = "demo-app"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
}
