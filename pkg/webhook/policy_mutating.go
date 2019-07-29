package webhook

import (
	"context"
	"net/http"
	"strings"

	opa "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission/builder"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	atypes "sigs.k8s.io/controller-runtime/pkg/webhook/admission/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
)

func init() {
	CreateWebhookFuncs = append(CreateWebhookFuncs, AddMutatingWebhook)
}

// AddMutatingWebhook creates the mutating webhook
// below: notations add permissions kube-mgmt needs. Access cannot yet be restricted on a namespace-level granularity
// +kubebuilder:rbac:groups=*,resources=*,verbs=get;list;watch
// +kubebuilder:rbac:groups=,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
func AddMutatingWebhook(mgr manager.Manager, opa opa.Client) (webhook.Webhook, error) {
	mutatingWH, err := builder.NewWebhookBuilder().
		Mutating().
		Name(*mutatingWHName).
		Path("/v1/mutate").
		Rules(admissionregistrationv1beta1.RuleWithOperations{
			Operations: []admissionregistrationv1beta1.OperationType{admissionregistrationv1beta1.Create, admissionregistrationv1beta1.Update},
			Rule: admissionregistrationv1beta1.Rule{
				APIGroups:   []string{"*"},
				APIVersions: []string{"*"},
				Resources:   []string{"*"},
			},
		}).
		Handlers(&mutationHandler{opa: opa, k8s: mgr.GetClient(), cfg: mgr.GetConfig(), decoder: mgr.GetAdmissionDecoder()}).
		WithManager(mgr).
		Build()
	if err != nil {
		return nil, err
	}

	return mutatingWH, nil
}

var _ admission.Handler = &mutationHandler{}

type mutationHandler struct {
	opa     opa.Client
	k8s     client.Client
	cfg     *rest.Config
	decoder atypes.Decoder
}

func addPodLabel(ctx context.Context, pod *corev1.Pod, key string, deflt string) error {
	log.Info("Adding label to pod", "object", pod)
	if pod.Labels == nil {
			pod.Labels = map[string]string{}
	}
	if _, exists := pod.Labels[key]; !exists {
		pod.Labels[key] = deflt // add label and default value
	}
	return nil
}

// Apply mutations to input objects
func (h *mutationHandler) Handle(ctx context.Context, req atypes.Request) atypes.Response {
	log := log.WithValues("hookType", "mutation")
	if isGkServiceAccount(req.AdmissionRequest.UserInfo) {
		return admission.ValidationResponse(true, "Gatekeeper does not self-manage")
	}

	crs, err := h.getAllCRs(ctx)
	if err != nil {
		log.Info("Failed to get CRs", "error", err)
		mResp := admission.ValidationResponse(true, err.Error())
		mResp.Response.Result.Code = http.StatusBadRequest
		return mResp
	}

	pod := &corev1.Pod{}
	_, _, err = deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, pod)
	if err != nil {
		log.Info("Decoding failed.", "error", err.Error())
		mResp := admission.ValidationResponse(true, err.Error())
		mResp.Response.Result.Code = http.StatusBadRequest
		return mResp
	}

	defVal := ""
	for ctKind, crList := range crs {
		log.Info("CT", "object" ,ctKind)
		for _, c := range crList.Items {
			log.Info("mutation obj", "object", c)
			rule, ok, err := unstructured.NestedString(c.Object, "spec", "parameters", "mutations", "foo")
			if err != nil {
				log.Info("Unable to access object fields", "error", err.Error())
			}
			if ok {
				defVal = rule
				log.Info("Nested labels", "object", rule)
			}
		}
	}

	patchObj := pod.DeepCopy()
	err = addPodLabel(ctx, patchObj, "jessicadl", defVal)
	if err != nil {
		log.Info("Could not apply mutations", "error", err.Error())
		mResp := admission.ValidationResponse(true, err.Error())
		mResp.Response.Result.Code = http.StatusInternalServerError
		return mResp
	}

	log.Info("Mutated.")
	mResp := admission.PatchResponse(pod, patchObj)

	return mResp
}

func (h *mutationHandler) getAllConstraintKinds() (*metav1.APIResourceList, error) {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(h.cfg)
	if err != nil {
		log.Info("Failed to create discovery client", "error", err.Error())
		return nil, err
	}
	return discoveryClient.ServerResourcesForGroupVersion("mutations.gatekeeper.sh/v1alpha1")
}

func (h *mutationHandler) getAllCRs(ctx context.Context) (map[string]unstructured.UnstructuredList, error) {
	crResources, err := h.getAllConstraintKinds()
	if err != nil {
		log.Info("Unable to get CRD kinds", "error", err.Error())
		return nil, err
	}

	resourceGV := strings.Split(crResources.GroupVersion, "/")
	group := resourceGV[0]
	version := resourceGV[1]
	constraintList := make(map[string]unstructured.UnstructuredList, len(crResources.APIResources))

	// get constraints for each Kind
	for _, r := range crResources.APIResources {
		log.Info("mutation", "resource kind", r.Kind)
		constraintGvk := schema.GroupVersionKind{
			Group:   group,
			Version: version,
			Kind:    r.Kind + "List",
		}
		instanceList := &unstructured.UnstructuredList{}
		instanceList.SetGroupVersionKind(constraintGvk)
		err := h.k8s.List(ctx, &client.ListOptions{}, instanceList)
		if err != nil {
			log.Info("Unable to list CRs", "error", err.Error())
			return nil, err
		}
		constraintList[r.Kind] = *instanceList
	}
	return constraintList, nil
}
