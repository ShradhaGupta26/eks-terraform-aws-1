locals {
  tolerations = [
    {
      key= "availability_zone",
      operator= "Exists"
      effect= "NoSchedule"
    },
    {
      key= "ec2_lifecycle",
      operator= "Exists"
      effect= "NoSchedule"
    },
    {
      key= "instance_type",
      operator= "Exists"
      effect= "NoSchedule"
    }
  ]
}

resource "helm_release" "cluster_autoscaler" {
  depends_on = [var.mod_dependency, kubernetes_namespace.cluster_autoscaler]
  count      = var.enabled ? 1 : 0
  name       = var.helm_chart_name
  chart      = var.helm_chart_release_name
  repository = var.helm_chart_repo
  version    = var.helm_chart_version
  namespace  = var.namespace

  set {
    name  = "fullnameOverride"
    value = var.fullname_override
  }

  set {
    name  = "autoDiscovery.clusterName"
    value = var.cluster_name
  }

  set {
    name  = "awsRegion"
    value = var.aws_region
  }

  set {
    name  = "image.repository"
    value = var.image_repository
  }

  set {
    name  = "image.tag"
    value = var.image_tag
  }

  set {
    name  = "rbac.serviceAccount.name"
    value = var.service_account_name
  }

  set {
    name  = "rbac.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.kubernetes_cluster_autoscaler[0].arn
  }

  dynamic "set" {
    for_each = local.tolerations
    iterator = each
    content {
      name      = "tolerations[${each.key}].key"
      value = each.value.key
    }
  }
  
  dynamic "set" {
    for_each = local.tolerations
    iterator = each
    content {
      name      = "tolerations[${each.key}].operator"
      value = each.value.operator
    }
  }

  dynamic "set" {
    for_each = local.tolerations
    iterator = each
    content {
      name      = "tolerations[${each.key}].effect"
      value = each.value.effect
    }
  }

  values = [
    yamlencode(var.settings)
  ]

}
