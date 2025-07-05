import bpy
import bmesh
import numpy as np

def create_smooth_hillside(name="SmoothHillside", size=24, subdivisions=200, seed=42):
    np.random.seed(seed)
    
    # Create a grid mesh
    bpy.ops.mesh.primitive_grid_add(
        x_subdivisions=subdivisions, 
        y_subdivisions=subdivisions, 
        size=size, 
        location=(0, 0, 0)
    )
    obj = bpy.context.active_object
    mesh = obj.data

    bm = bmesh.new()
    bm.from_mesh(mesh)

    # Smooth hillside with gentle undulations
    for v in bm.verts:
        x, y = v.co.x, v.co.y

        # Main slope
        slope = (x * 0.45) + (y * 0.1)

        # Gentle broad undulations (no rocks)
        height = (
            3 * np.exp(-((x-2)**2/100 + (y+5)**2/180)) +
            1.2 * np.exp(-((x+8)**2/120 + (y+2)**2/100))
        )

        # Tiny variation for naturalness (no visible rocks)
        gentle_noise = 0.18 * np.sin(0.15*x + 0.22*y + seed)

        v.co.z = slope + height + gentle_noise

    bm.to_mesh(mesh)
    bm.free()

    # Optional: Subsurf for extra smoothness
    subsurf = obj.modifiers.new(name='Subdivision', type='SUBSURF')
    subsurf.levels = 2
    subsurf.render_levels = 3

    # Shade smooth
    bpy.ops.object.shade_smooth()
    obj.name = name

    # Add a grassy material
    mat = bpy.data.materials.new(name="GrassyHillside")
    mat.use_nodes = True
    nodes = mat.node_tree.nodes
    links = mat.node_tree.links

    # Clear default nodes
    for n in nodes:
        nodes.remove(n)
    output = nodes.new(type="ShaderNodeOutputMaterial")
    diffuse = nodes.new(type="ShaderNodeBsdfDiffuse")
    colorramp = nodes.new(type="ShaderNodeValToRGB")
    geometry = nodes.new(type="ShaderNodeNewGeometry")

    # Grass color ramp (inspired by image)
    colorramp.color_ramp.elements.new(0.5)
    colorramp.color_ramp.elements[0].color = (0.33, 0.41, 0.18, 1)
    colorramp.color_ramp.elements[1].color = (0.48, 0.62, 0.20, 1)
    colorramp.color_ramp.elements[2].color = (0.60, 0.65, 0.30, 1)

    links.new(geometry.outputs['Normal'], colorramp.inputs['Fac'])
    links.new(colorramp.outputs['Color'], diffuse.inputs['Color'])
    links.new(diffuse.outputs['BSDF'], output.inputs['Surface'])

    obj.data.materials.append(mat)

# Remove all objects
bpy.ops.object.select_all(action='SELECT')
bpy.ops.object.delete(use_global=False)

# Create the smooth grassy hillside
create_smooth_hillside()
