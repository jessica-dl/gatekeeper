package webhook

import (
	"context"
	"net/http"

	opa "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission/builder"
	atypes "sigs.k8s.io/controller-runtime/pkg/webhook/admission/types"
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
		Name(mutatingWHName).
		Path("/v1/mutate").
		Rules(admissionregistrationv1beta1.RuleWithOperations{
			Operations: []admissionregistrationv1beta1.OperationType{admissionregistrationv1beta1.Create, admissionregistrationv1beta1.Update},
			Rule: admissionregistrationv1beta1.Rule{
				APIGroups:   []string{"*"},
				APIVersions: []string{"*"},
				Resources:   []string{"*"},
			},
		}).
		Handlers(&mutationHandler{opa: opa, k8s: mgr.GetClient()}).
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
	decoder atypes.Decoder
}

func mutatePods(ctx context.Context, pod *corev1.Pod) error {
	log.Info("Trying to mutate pod", "object", pod)
	if pod.Labels == nil {
			pod.Labels = map[string]string{}
	}
	pod.Labels["someLabel"] = "jessicadl"
	return nil
}

// Apply mutations to input objects
func (h *mutationHandler) Handle(ctx context.Context, req atypes.Request) atypes.Response {
	log := log.WithValues("hookType", "mutation")
	defer log.Info("Finished mutating")

	mResp := admission.ValidationResponse(false, "default")

	pod := &corev1.Pod{}
	log.Info("Attempt to decode")
	err := h.decoder.Decode(req, pod)
	if err != nil {
		log.Info("Decoding failed.")
		mResp.Response.Result.Code = http.StatusBadRequest
	}

	patchObj := pod.DeepCopy()

	err = mutatePods(ctx, patchObj)
	if err != nil {
		log.Info("Could not apply mutations.")
		mResp.Response.Result.Code = http.StatusInternalServerError
	}
	log.Info("mutated pods")
	mResp = admission.PatchResponse(pod, patchObj)

	return mResp
}

/*
func isGkServiceAccount(user authenticationv1.UserInfo) bool {
	saGroup := fmt.Sprintf("system:serviceaccounts:%s", namespace)
	for _, g := range user.Groups {
		if g == saGroup {
			return true
		}
	}
	return false
}

// validateGatekeeperResources returns whether an issue is user error (vs internal) and any errors
// validating internal resources
func (h *mutationHandler) validateGatekeeperResources(ctx context.Context, req atypes.Request) (bool, error) {
	if req.AdmissionRequest.Kind.Group == "templates.gatekeeper.sh" && req.AdmissionRequest.Kind.Kind == "MutationTemplate" {
		return h.validateTemplate(ctx, req)
	}

	// find out what this is named (mutations.gatekeeper.sh?)
	if req.AdmissionRequest.Kind.Group == "constraints.gatekeeper.sh" {
		return h.validateConstraint(ctx, req)
	}

	return false, nil
}

func (h *mutationHandler) validateTemplate(ctx context.Context, req atypes.Request) (bool, error) {
	templ := &templv1alpha1.MutationTemplate{}
	if _, _, err := deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, templ); err != nil {
		return false, err
	}
	if _, err := h.opa.CreateCRD(ctx, templ); err != nil {
		return true, err
	}
	return false, nil
}
*/
