package webhook

import (
	"context"
<<<<<<< HEAD
	"net/http"
=======
>>>>>>> 631d3e2... Add a mutating webhook to GK.

	opa "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission/builder"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	atypes "sigs.k8s.io/controller-runtime/pkg/webhook/admission/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	constraintsGV = "constraints.gatekeeper.sh/v1alpha1"
)

func init() {
	CreateWebhookFuncs = append(CreateWebhookFuncs, AddMutatingWebhook)
}

<<<<<<< HEAD
// AddMutatingWebhook creates the mutating webhook
=======
// AddMutatingWebhook creates the mutating webhook
>>>>>>> c6c19e0... Added logs for debugging
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

func dummyMutation(ctx context.Context, pod *corev1.Pod) error {
	log.Info("Trying to mutate pod", "object", pod)
	if pod.Labels == nil {
			pod.Labels = map[string]string{}
	}
	pod.Labels["someLabel"] = "jessicadl"
	return nil
}

func addPodLabel(ctx context.Context, pod *corev1.Pod, key string, deflt string) error {
	log.Info("Adding label to pod", "object", pod)
	if _, exists := pod.Labels[key]; !exists {
		pod.Labels[key] = deflt // add label and default value
	}
	return nil
}

// Apply mutations to input objects
func (h *mutationHandler) Handle(ctx context.Context, req atypes.Request) atypes.Response {
	log := log.WithValues("hookType", "mutation")

	crs, err := h.getAllConstraintKinds()
	log.Info("Got CRs", "object", crs)
	if err != nil {
		log.Info("Could not access CRs.")
		mResp := admission.ValidationResponse(false, err.Error())
		mResp.Response.Result.Code = http.StatusInternalServerError
		return mResp
	}

	pod := &corev1.Pod{}
	_, _, err = deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, pod)
	if err != nil {
		log.Info("Decoding failed.", "error", err)
	  mResp := admission.ValidationResponse(false, err.Error())
		mResp.Response.Result.Code = http.StatusBadRequest
		return mResp
	}

	patchObj := pod.DeepCopy()

	err = addPodLabel(ctx, patchObj, "jessicadl", "foo")
	if err != nil {
		log.Info("Could not apply mutations.")
		mResp := admission.ValidationResponse(false, err.Error())
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
		return nil, err
	}
	return discoveryClient.ServerResourcesForGroupVersion(constraintsGV)
}
