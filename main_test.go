package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func TestGetImagesForPods(t *testing.T) {

	t.Run("ReturnsEmptyListForNoPods", func(t *testing.T) {

		pods := []v1.Pod{}

		// act
		images := getImagesForPods(pods)

		assert.Equal(t, 0, len(images))
	})

	t.Run("ReturnsImagesForAllPodContainers", func(t *testing.T) {

		image0 := "estafette/estafette-ci-api:1.0.0"
		image1 := "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47"

		pods := []v1.Pod{
			{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Image: image0,
						},
						{
							Image: image1,
						},
					},
				},
			},
		}

		// act
		images := getImagesForPods(pods)

		if assert.Equal(t, 2, len(images)) {
			assert.Equal(t, "estafette/estafette-ci-api:1.0.0", images[0])
			assert.Equal(t, "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47", images[1])
		}
	})

	t.Run("ReturnsImagesForAllPodContainersIncludingInitContainers", func(t *testing.T) {

		image0 := "estafette/estafette-ci-api-init:1.0.0"
		image1 := "estafette/estafette-ci-api:1.0.0"
		image2 := "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47"

		pods := []v1.Pod{
			{
				Spec: v1.PodSpec{
					InitContainers: []v1.Container{
						{
							Image: image0,
						},
					},
					Containers: []v1.Container{
						{
							Image: image1,
						},
						{
							Image: image2,
						},
					},
				},
			},
		}

		// act
		images := getImagesForPods(pods)

		if assert.Equal(t, 3, len(images)) {
			assert.Equal(t, "estafette/estafette-ci-api-init:1.0.0", images[0])
			assert.Equal(t, "estafette/estafette-ci-api:1.0.0", images[1])
			assert.Equal(t, "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47", images[2])
		}
	})

	t.Run("ReturnsImagesForMultiplePods", func(t *testing.T) {

		imageA0 := "estafette/estafette-ci-api:1.0.0"
		imageA1 := "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47"
		imageB0 := "estafette/estafette-ci-web:1.0.0"
		imageB1 := "estafette/openresty-sidecar:0.8.0-opentracing"

		pods := []v1.Pod{
			{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Image: imageA0,
						},
						{
							Image: imageA1,
						},
					},
				},
			},
			{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Image: imageB0,
						},
						{
							Image: imageB1,
						},
					},
				},
			},
		}

		// act
		images := getImagesForPods(pods)

		if assert.Equal(t, 4, len(images)) {
			assert.Equal(t, "estafette/estafette-ci-api:1.0.0", images[0])
			assert.Equal(t, "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47", images[1])
			assert.Equal(t, "estafette/estafette-ci-web:1.0.0", images[2])
			assert.Equal(t, "estafette/openresty-sidecar:0.8.0-opentracing", images[3])
		}
	})

	t.Run("ReturnsImagesWithoutDeduping", func(t *testing.T) {

		imageA0 := "estafette/estafette-ci-api-init:1.0.0"
		imageA1 := "estafette/estafette-ci-api:1.0.0"
		imageA2 := "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47"
		imageB0 := "estafette/estafette-ci-api-init:1.0.0"
		imageB1 := "estafette/estafette-ci-api:1.0.0"
		imageB2 := "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47"

		pods := []v1.Pod{
			{
				Spec: v1.PodSpec{
					InitContainers: []v1.Container{
						{
							Image: imageA0,
						},
					},
					Containers: []v1.Container{
						{
							Image: imageA1,
						},
						{
							Image: imageA2,
						},
					},
				},
			},
			{
				Spec: v1.PodSpec{
					InitContainers: []v1.Container{
						{
							Image: imageB0,
						},
					},
					Containers: []v1.Container{
						{
							Image: imageB1,
						},
						{
							Image: imageB2,
						},
					},
				},
			},
		}

		// act
		images := getImagesForPods(pods)

		if assert.Equal(t, 6, len(images)) {
			assert.Equal(t, "estafette/estafette-ci-api-init:1.0.0", images[0])
			assert.Equal(t, "estafette/estafette-ci-api:1.0.0", images[1])
			assert.Equal(t, "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47", images[2])
			assert.Equal(t, "estafette/estafette-ci-api-init:1.0.0", images[3])
			assert.Equal(t, "estafette/estafette-ci-api:1.0.0", images[4])
			assert.Equal(t, "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47", images[5])
		}
	})
}

func TestDedupeImages(t *testing.T) {

	t.Run("ReturnsEmptyListForNoImages", func(t *testing.T) {

		images := []string{}

		// act
		dedupedImages := dedupeImages(images)

		assert.Equal(t, 0, len(dedupedImages))
	})

	t.Run("ReturnsSameListIfThereAreNoDuplicated", func(t *testing.T) {

		images := []string{
			"estafette/estafette-ci-api-init:1.0.0",
			"estafette/estafette-ci-api:1.0.0",
			"estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47",
		}

		// act
		dedupedImages := dedupeImages(images)

		assert.Equal(t, 3, len(dedupedImages))
		assert.Equal(t, "estafette/estafette-ci-api-init:1.0.0", dedupedImages[0])
		assert.Equal(t, "estafette/estafette-ci-api:1.0.0", dedupedImages[1])
		assert.Equal(t, "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47", dedupedImages[2])
	})

	t.Run("ReturnsListWithoutDuplicatesIfThereAreDuplicates", func(t *testing.T) {

		images := []string{
			"estafette/estafette-ci-api-init:1.0.0",
			"estafette/estafette-ci-api:1.0.0",
			"estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47",
			"estafette/estafette-ci-api-init:1.0.0",
			"estafette/estafette-ci-api:1.0.0",
			"estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47",
		}

		// act
		dedupedImages := dedupeImages(images)

		assert.Equal(t, 3, len(dedupedImages))
		assert.Equal(t, "estafette/estafette-ci-api-init:1.0.0", dedupedImages[0])
		assert.Equal(t, "estafette/estafette-ci-api:1.0.0", dedupedImages[1])
		assert.Equal(t, "estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47", dedupedImages[2])
	})
}

type mockScanner struct {
	ScanImageFunc      func(image string) (vulnerabilityReports []VulnerabilityReport, err error)
	UpdateDatabaseFunc func() (err error)
}

func (s mockScanner) ScanImage(image string) (vulnerabilityReports []VulnerabilityReport, err error) {
	if s.ScanImageFunc == nil {
		return
	}
	return s.ScanImageFunc(image)
}

func (s mockScanner) UpdateDatabase() (err error) {
	if s.UpdateDatabaseFunc == nil {
		return
	}
	return s.UpdateDatabaseFunc()
}

func TestScanImages(t *testing.T) {

	t.Run("DoesNotCallScanImageForEmptyListOfImages", func(t *testing.T) {

		vulnerabilityReportState := map[string]map[string]float64{}
		images := []string{}

		callCount := 0
		scanner := mockScanner{}
		scanner.ScanImageFunc = func(image string) (vulnerabilityReports []VulnerabilityReport, err error) {
			callCount++
			return
		}

		// act
		scanImages(scanner, vulnerabilityReportState, images, nil, nil, nil, true)

		assert.Equal(t, 0, callCount)
	})

	t.Run("CallsScanImageForEveryImage", func(t *testing.T) {

		images := []string{
			"estafette/estafette-ci-api:1.0.0",
			"estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47",
		}

		vulnerabilityReportState := map[string]map[string]float64{}

		callCount := 0
		scanner := mockScanner{}
		scanner.ScanImageFunc = func(image string) (vulnerabilityReports []VulnerabilityReport, err error) {
			callCount++
			return
		}

		// act
		scanImages(scanner, vulnerabilityReportState, images, nil, nil, nil, true)

		assert.Equal(t, 2, callCount)
	})

	t.Run("CallsUpdateDatabaseOnce", func(t *testing.T) {

		images := []string{
			"estafette/estafette-ci-api:1.0.0",
			"estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47",
			"estafette/estafette-ci-web:1.0.0",
			"estafette/openresty-sidecar:0.8.0-opentracing",
		}

		vulnerabilityReportState := map[string]map[string]float64{}

		callCount := 0
		scanner := mockScanner{}
		scanner.UpdateDatabaseFunc = func() (err error) {
			callCount++
			return
		}

		// act
		scanImages(scanner, vulnerabilityReportState, images, nil, nil, nil, true)

		assert.Equal(t, 1, callCount)
	})
}

func TestPurgeObsoleteState(t *testing.T) {

	t.Run("KeepsAllStateIfEveryImageIsInUseByCluster", func(t *testing.T) {

		images := []string{
			"estafette/estafette-ci-api:1.0.0",
			"estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47",
		}

		vulnerabilityReportState := map[string]map[string]float64{
			"estafette/estafette-ci-api:1.0.0": map[string]float64{},
			"estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47": map[string]float64{},
		}

		// act
		purgeObsoleteState(vulnerabilityReportState, images)

		assert.Equal(t, 2, len(vulnerabilityReportState))
	})

	t.Run("PurgesAnImageFromStateIfItsNotUsedByCluster", func(t *testing.T) {

		images := []string{
			"estafette/estafette-ci-api:1.0.0",
		}

		vulnerabilityReportState := map[string]map[string]float64{
			"estafette/estafette-ci-api:1.0.0": map[string]float64{},
			"estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47": map[string]float64{},
		}

		// act
		purgeObsoleteState(vulnerabilityReportState, images)

		assert.Equal(t, 1, len(vulnerabilityReportState))
		assert.Equal(t, map[string]float64{}, vulnerabilityReportState["estafette/estafette-ci-api:1.0.0"])
	})

	t.Run("PurgesAllImagesFromStateIfItsNotUsedByCluster", func(t *testing.T) {

		images := []string{
			"estafette/estafette-ci-api:1.0.1",
			"estafette/openresty-sidecar:1.5.8.2",
		}

		vulnerabilityReportState := map[string]map[string]float64{
			"estafette/estafette-ci-api:1.0.0": map[string]float64{},
			"estafette/openresty-sidecar@sha256:1a58f708fed5d04074c2dcbe293d46eacec4f10fcd2fc86dc6b6885ea2246e47": map[string]float64{},
		}

		// act
		purgeObsoleteState(vulnerabilityReportState, images)

		assert.Equal(t, 0, len(vulnerabilityReportState))
	})
}

func TestGroupReportPerLevel(t *testing.T) {

	t.Run("ReturnsEmptyMapForEmptyVulnerabilityReportArray", func(t *testing.T) {

		vulnerabilityReports := []VulnerabilityReport{}

		// act
		groupedReport := groupReportPerLevel(vulnerabilityReports)

		assert.Equal(t, 0, len(groupedReport))
	})

	t.Run("ReturnsMapWithCountPerSeverityForAllVulnerabilitiesInVulnerabilityReportArrayWithFix", func(t *testing.T) {

		vulnerabilityReports := []VulnerabilityReport{
			VulnerabilityReport{
				Target: "alpine:3.9 (alpine 3.9.4)",
				Vulnerabilities: []Vulnerability{
					Vulnerability{
						VulnerabilityID:  "CVE-2019-14697",
						PkgName:          "musl",
						InstalledVersion: "1.1.20-r4",
						FixedVersion:     "1.1.20-r5",
						Severity:         "HIGH",
					},
					Vulnerability{
						VulnerabilityID:  "CVE-2019-1549",
						PkgName:          "openssl",
						InstalledVersion: "1.1.1b-r1",
						FixedVersion:     "1.1.1d-r0",
						Severity:         "MEDIUM",
					},
					Vulnerability{
						VulnerabilityID:  "CVE-2019-1551",
						PkgName:          "openssl",
						InstalledVersion: "1.1.1b-r1",
						FixedVersion:     "1.1.1d-r2",
						Severity:         "MEDIUM",
					},
					Vulnerability{
						VulnerabilityID:  "CVE-2019-1563",
						PkgName:          "openssl",
						InstalledVersion: "1.1.1b-r1",
						FixedVersion:     "1.1.1d-r0",
						Severity:         "MEDIUM",
					},
					Vulnerability{
						VulnerabilityID:  "CVE-2019-1547",
						PkgName:          "openssl",
						InstalledVersion: "1.1.1b-r1",
						FixedVersion:     "1.1.1d-r0",
						Severity:         "LOW",
					},
				},
			},
		}

		// act
		groupedReport := groupReportPerLevel(vulnerabilityReports)

		assert.Equal(t, 3, len(groupedReport))
		assert.Equal(t, float64(1), groupedReport["HIGH"])
		assert.Equal(t, float64(3), groupedReport["MEDIUM"])
		assert.Equal(t, float64(1), groupedReport["LOW"])
	})

	t.Run("ReturnsMapWithCountPerSeverityForAllVulnerabilitiesInVulnerabilityReportArrayExcludingUnfixedOnes", func(t *testing.T) {

		vulnerabilityReports := []VulnerabilityReport{
			VulnerabilityReport{
				Target: "alpine:3.9 (alpine 3.9.4)",
				Vulnerabilities: []Vulnerability{
					Vulnerability{
						VulnerabilityID:  "CVE-2019-14697",
						PkgName:          "musl",
						InstalledVersion: "1.1.20-r4",
						FixedVersion:     "1.1.20-r5",
						Severity:         "HIGH",
					},
					Vulnerability{
						VulnerabilityID:  "CVE-2019-1549",
						PkgName:          "openssl",
						InstalledVersion: "1.1.1b-r1",
						FixedVersion:     "1.1.1d-r0",
						Severity:         "MEDIUM",
					},
					Vulnerability{
						VulnerabilityID:  "CVE-2019-1551",
						PkgName:          "openssl",
						InstalledVersion: "1.1.1b-r1",
						FixedVersion:     "",
						Severity:         "MEDIUM",
					},
					Vulnerability{
						VulnerabilityID:  "CVE-2019-1563",
						PkgName:          "openssl",
						InstalledVersion: "1.1.1b-r1",
						FixedVersion:     "1.1.1d-r0",
						Severity:         "MEDIUM",
					},
					Vulnerability{
						VulnerabilityID:  "CVE-2019-1547",
						PkgName:          "openssl",
						InstalledVersion: "1.1.1b-r1",
						FixedVersion:     "1.1.1d-r0",
						Severity:         "LOW",
					},
				},
			},
		}

		// act
		groupedReport := groupReportPerLevel(vulnerabilityReports)

		assert.Equal(t, 3, len(groupedReport))
		assert.Equal(t, float64(1), groupedReport["HIGH"])
		assert.Equal(t, float64(2), groupedReport["MEDIUM"])
		assert.Equal(t, float64(1), groupedReport["LOW"])
	})
}
