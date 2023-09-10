# Kopf operator to maintain CNAME

This operator maintains CNAMEs in an Azure DNS Zone based on the annotation `cname` in an ingress object:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kopf-example-2
  annotations:
    cnames: blog.asksven.io=cname1,foo.asksven.io=cname2
```

## Run

1. `pip install -r requirements.txt`
1. Create `setenv` based on `setenv.template`
1. `source setenv`
1. Run: `kopf run -A cname_operator.py`
