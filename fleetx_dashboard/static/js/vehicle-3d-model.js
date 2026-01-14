/**
 * 3D Model Integration for FleetX Dashboard
 * This file overrides the vehicle icon creation to use 3D GLB models
 */

// ============== 3D MODEL GLOBALS ==============
let car3DModel = null;
let modelScene = null;
let modelCamera = null;
let modelRenderer = null;
let modelLoaded = false;

// ============== 3D MODEL LOADING ==============
function init3DModel() {
    // Check if WebGL is available
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) {
            console.warn('WebGL not available, 3D models will not be rendered');
            return;
        }
    } catch (e) {
        console.warn('WebGL not available:', e);
        return;
    }

    // Create a scene for the 3D model
    modelScene = new THREE.Scene();

    // Create camera with isometric view - will be adjusted after model loads
    modelCamera = new THREE.OrthographicCamera(-5, 5, 5, -5, 0.1, 1000);
    modelCamera.position.set(-16, 8, 20); // Isometric angle position
    modelCamera.lookAt(0, 0, 0); // Look at the model center

    // Create renderer with error handling
    try {
        modelRenderer = new THREE.WebGLRenderer({
            alpha: true,
            antialias: true,
            preserveDrawingBuffer: true
        });
    } catch (e) {
        console.error('Failed to create WebGL renderer:', e);
        return;
    }

    // Add lighting for better visibility
    // Ambient light for overall illumination
    const ambientLight = new THREE.AmbientLight(0xffffff, 1.2);
    modelScene.add(ambientLight);

    // Hemisphere light for outdoor feel (sky and ground)
    const hemisphereLight = new THREE.HemisphereLight(0xffffff, 0x444444, 1.2);
    modelScene.add(hemisphereLight);

    // Main directional light from top-front
    const directionalLight1 = new THREE.DirectionalLight(0xffffff, 1.2);
    directionalLight1.position.set(5, 10, 5);
    modelScene.add(directionalLight1);

    // Fill light from the opposite side
    const directionalLight2 = new THREE.DirectionalLight(0xffffff, 1.2);
    directionalLight2.position.set(-5, 5, -5);
    modelScene.add(directionalLight2);

    // Back light for rim lighting effect
    const directionalLight3 = new THREE.DirectionalLight(0xffffff, 0.3);
    directionalLight3.position.set(0, 5, -10);
    modelScene.add(directionalLight3);

    // Load the GLB model
    const loader = new THREE.GLTFLoader();
    loader.load(
        '/static/assets/car.glb',
        function(gltf) {
            car3DModel = gltf.scene;

            // Get model dimensions for debugging
            const box = new THREE.Box3().setFromObject(car3DModel);
            const size = box.getSize(new THREE.Vector3());
            console.log('Model loaded! Original dimensions:', size);
            console.log('Model position:', car3DModel.position);
            console.log('Model rotation:', car3DModel.rotation);
            console.log('Model scale:', car3DModel.scale);

            // Center the model
            const center = box.getCenter(new THREE.Vector3());
            car3DModel.position.sub(center);

            // Dynamic scaling - target size based on model dimensions
            // For very large models (>100 units), scale to 3 units
            // For medium models (10-100 units), scale to 2.5 units
            // For small models (<10 units), scale to 2 units
            const maxDimension = Math.max(size.x, size.y, size.z);
            let targetSize;
            if (maxDimension > 100) {
                targetSize = 3; // Large models need more space
            } else if (maxDimension > 10) {
                targetSize = 2.5;
            } else {
                targetSize = 2;
            }

            const scale = targetSize / maxDimension;
            car3DModel.scale.set(scale, scale, scale);

            // Adjust camera to fit the scaled model
            const scaledSize = targetSize;
            const cameraSize = scaledSize * 1.5; // Add 50% padding
            modelCamera.left = -cameraSize;
            modelCamera.right = cameraSize;
            modelCamera.top = cameraSize;
            modelCamera.bottom = -cameraSize;
            modelCamera.updateProjectionMatrix();

            console.log('After scaling - Model scale:', car3DModel.scale);
            console.log('Target size:', targetSize, 'units');
            console.log('Camera bounds adjusted to:', cameraSize);
            console.log('Model should now be visible!');

            // Add to scene
            modelScene.add(car3DModel);
            modelLoaded = true;
            console.log('3D car model loaded and added to scene successfully');

            // Update all existing markers once model is loaded
            if (typeof updateVehicleMarkers === 'function') {
                updateVehicleMarkers();
            }
        },
        function(xhr) {
            const percentComplete = xhr.total > 0 ? (xhr.loaded / xhr.total * 100) : 0;
            console.log('Loading model: ' + percentComplete.toFixed(2) + '% loaded');
        },
        function(error) {
            console.error('Error loading 3D model:', error);
            console.error('Make sure /static/assets/car.glb exists and is a valid GLB file');
            modelLoaded = false;
        }
    );
}

function render3DModelToCanvas(size, bearing, statusColor) {
    if (!modelLoaded || !car3DModel) {
        return null;
    }

    // Set renderer size
    modelRenderer.setSize(size[0], size[1]);

    // Rotate the model based on bearing
    // Note: If your GLB model's front doesn't face forward by default,
    // add an offset here (e.g., -90° if the front faces right in the model)
    // Uncomment and adjust if needed:
    // const bearingOffset = -90; // Adjust this value based on your model's default orientation
    // car3DModel.rotation.y = THREE.MathUtils.degToRad(bearing + bearingOffset);

    car3DModel.rotation.y = THREE.MathUtils.degToRad(bearing);

    // Keep original texture - status color disabled
    // If you want to tint by status color, uncomment the code below:
    /*
    if (statusColor) {
        car3DModel.traverse((child) => {
            if (child.isMesh) {
                if (!child.material.userData.originalColor) {
                    child.material.userData.originalColor = child.material.color.clone();
                }
                child.material = child.material.clone();
                child.material.color.setStyle(statusColor);
            }
        });
    }
    */

    // Render the scene
    modelRenderer.render(modelScene, modelCamera);

    // Get the canvas as data URL
    return modelRenderer.domElement.toDataURL();
}

// Override the createVehicleIcon function
const originalCreateVehicleIcon = window.createVehicleIcon;
window.createVehicleIcon = function(vehicle, zoomLevel) {
    const statusColor = getStatusColor(vehicle.status);
    const bearing = vehicle.bearing || 0;

    let iconSize, anchorSize, content;

    if (zoomLevel < 8) {
        // Level 1: Simple dot
        iconSize = [12, 12];
        anchorSize = [6, 6];
        content = `
            <svg width="${iconSize[0]}" height="${iconSize[1]}" viewBox="0 0 12 12" xmlns="http://www.w3.org/2000/svg">
                <circle cx="6" cy="6" r="5" fill="${statusColor}" stroke="white" stroke-width="1"/>
            </svg>
        `;
    } else if (zoomLevel < 11) {
        // Level 2: Small 3D model
        iconSize = [90, 135];
        anchorSize = [45, 67];

        if (modelLoaded) {
            const dataUrl = render3DModelToCanvas(iconSize, bearing, statusColor);
            if (dataUrl) {
                content = `<img src="${dataUrl}" style="width: ${iconSize[0]}px; height: ${iconSize[1]}px;" />`;
            } else {
                content = `<div style="width: ${iconSize[0]}px; height: ${iconSize[1]}px; background: ${statusColor}; border-radius: 50%; border: 2px solid white;"></div>`;
            }
        } else {
            content = `<div style="width: ${iconSize[0]}px; height: ${iconSize[1]}px; background: ${statusColor}; border-radius: 50%; border: 2px solid white;"></div>`;
        }
    } else if (zoomLevel < 14) {
        // Level 3: Medium 3D model
        iconSize = [120, 180];
        anchorSize = [60, 90];

        if (modelLoaded) {
            const dataUrl = render3DModelToCanvas(iconSize, bearing, statusColor);
            if (dataUrl) {
                content = `<img src="${dataUrl}" style="width: ${iconSize[0]}px; height: ${iconSize[1]}px;" />`;
            } else {
                content = `<div style="width: ${iconSize[0]}px; height: ${iconSize[1]}px; background: ${statusColor}; border-radius: 50%; border: 2px solid white;"></div>`;
            }
        } else {
            content = `<div style="width: ${iconSize[0]}px; height: ${iconSize[1]}px; background: ${statusColor}; border-radius: 50%; border: 2px solid white;"></div>`;
        }
    } else {
        // Level 4: Large 3D model (zoom 14+)
        iconSize = [160, 240];
        anchorSize = [80, 120];

        if (modelLoaded) {
            const dataUrl = render3DModelToCanvas(iconSize, bearing, statusColor);
            if (dataUrl) {
                content = `<img src="${dataUrl}" style="width: ${iconSize[0]}px; height: ${iconSize[1]}px;" />`;
            } else {
                content = `<div style="width: ${iconSize[0]}px; height: ${iconSize[1]}px; background: ${statusColor}; border-radius: 50%; border: 2px solid white;"></div>`;
            }
        } else {
            content = `<div style="width: ${iconSize[0]}px; height: ${iconSize[1]}px; background: ${statusColor}; border-radius: 50%; border: 2px solid white;"></div>`;
        }
    }

    return L.divIcon({
        className: 'vehicle-marker',
        html: content,
        iconSize: iconSize,
        iconAnchor: anchorSize,
        popupAnchor: [0, -anchorSize[1]]
    });
};

// Initialize 3D model when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init3DModel);
} else {
    init3DModel();
}